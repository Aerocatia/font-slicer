// Font Slicer, by Aerocatia

#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

enum signatures {
    TAG_HEADER_SIGNATURE = 0x626C616D, // 'blam'
    FONT_SIGNATURE = 0x666F6E74, // 'font'
    NULL_SIGNATURE = 0xFFFFFFFF
};

struct tag_header {
	char pad1[36];
	uint32_t tag_group;
	uint32_t checksum;
	uint32_t offset;
	uint32_t size;
	char pad2[4];
	uint16_t version;
	char pad3;
	uint8_t unused_index; // always 255
	uint32_t signature; // always 'blam'
};
static_assert(sizeof(struct tag_header) == 64);

struct tag_reflexive {
	uint32_t count;
	uint32_t address; // 32-bit pointer to array
	uint32_t definition; // 32-bit pointer to tag definition (in-engine only)
};
static_assert(sizeof(struct tag_reflexive) == 12);

struct tag_data {
	uint32_t size;
	char pad[4];
	uint32_t file_offset;
	uint32_t address; // 32-bit pointer to data
	uint32_t definition;// 32-bit pointer to data definition (in-engine only)
};
static_assert(sizeof(struct tag_data) == 20);

struct tag_reference {
	uint32_t tag_group;
	uint32_t name; // 32-bit pointer to name
	uint32_t name_length;
	uint32_t index; //tag index (two-part tag id)
};
static_assert(sizeof(struct tag_reference) == 16);

struct font_character {
	uint16_t character;
	int16_t character_width;
	int16_t bitmap_width;
	int16_t bitmap_height;
	int16_t bitmap_origin_x;
	int16_t bitmap_origin_y;
	uint16_t hardware_character_index;
	char pad[2];
	uint32_t pixels_offset; // offset into pixels buffer
};
static_assert(sizeof(struct font_character) == 20);

#define STYLE_FONTS_COUNT 4
struct font_base {
	uint32_t flags;
	int16_t ascending_height;
	int16_t descending_height;
	int16_t leading_height;
	int16_t leading_width;
	char pad[36];
	struct tag_reflexive character_tables; // we don't care about these.
	struct tag_reference style_fonts[STYLE_FONTS_COUNT];
	struct tag_reflexive characters;
	struct tag_data pixels;
};
static_assert(sizeof(struct font_base) == 156);

static uint16_t byteswap16(uint16_t value) {
    return (value << 8) | (value >> 8);
}

static uint32_t byteswap32(uint32_t value) {
    return ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | ((value & 0xFF0000) >> 8) | (value >> 24);
}

static size_t calculate_pixels_size(int16_t width, int16_t height) {
    size_t pixels_size = 0;
    // Ask bungie
    if(width > 0 && height > 0) {
        pixels_size = width * height;
    }

    return pixels_size;
}

static int compare_characters(const void *a, const void *b) {
    uint16_t value_a = *(const uint16_t *)a;
    uint16_t value_b = *(const uint16_t *)b;

    if(value_a < value_b) {
        return -1;
    }
    else if (value_a > value_b) {
        return 1;
    }

     return 0;
}

static bool split_font_tag(const char *tag_path, const char *output_dir) {
    FILE *file_in = nullptr;
    uint8_t *buffer_in = nullptr;
    size_t buffer_in_size = 0;

    // Open font tag
    file_in = fopen(tag_path, "rb");
    if(!file_in) {
        fprintf(stderr, "Failed to open %s.\n", tag_path);
        return false;
    }

    // Get size and check if big enough
    fseek(file_in, 0, SEEK_END);
    buffer_in_size = ftell(file_in);
    fseek(file_in, 0, SEEK_SET);
    if(buffer_in_size < sizeof(struct tag_header) + sizeof(struct font_base)) {
        fprintf(stderr, "%s is too small to be a valid font tag.\n", tag_path);
        return false;
    }

    // Read into buffer
    buffer_in = malloc(buffer_in_size);
    if(!buffer_in) {
        fprintf(stderr, "Could not allocate %zu bytes.", buffer_in_size);
        return false;
    }

    if(fread(buffer_in, buffer_in_size, 1, file_in) != 1) {
        fprintf(stderr, "Could not read from %s.\n", tag_path);
        return false;
    }

    fclose(file_in);
    file_in = nullptr;

    // Check if it's really a font tag
    struct tag_header *header = (struct tag_header *)buffer_in;
    if(byteswap32(header->signature) != TAG_HEADER_SIGNATURE && byteswap32(header->tag_group) != FONT_SIGNATURE) {
        fprintf(stderr, "%s is not a valid font tag\n", tag_path);
        return false;
    }

    struct font_base *font = (struct font_base *)(buffer_in + sizeof(struct tag_header));

    // do we even have characters?
    uint32_t characters_count = byteswap32(font->characters.count);
    if(characters_count == 0) {
        fprintf(stderr, "%s has no characters to split.\n", tag_path);
        return false;
    }

    // No.
    if(font->character_tables.count != 0) { // don't need to byteswap for this check
        fprintf(stderr, "%s has character tables. I don't want to deal with this so please strip the tag with invader first.\n", tag_path);
        return false;
    }

    // do we have pixel data?
    size_t pixel_data_size = byteswap32(font->pixels.size);
    if(pixel_data_size == 0) {
        fprintf(stderr, "%s has no pixel data.\n", tag_path);
        return false;
    }

    // Get the offset to character data
    size_t characters_offset = sizeof(struct tag_header) + sizeof(struct font_base);

    // Add up any paths from the references.
    for(int i = 0; i < STYLE_FONTS_COUNT; i++) {
        uint32_t name_legnth = byteswap32(font->style_fonts[i].name_length);
        if(name_legnth != 0) {
            characters_offset += name_legnth + 1;
        }
    }

    // Get the offset to pixel data
    size_t pixel_data_offset = characters_offset + characters_count * sizeof(struct font_character);
    if(buffer_in_size != pixel_data_offset + pixel_data_size) {
        fprintf(stderr, "%s is fucked.\n", tag_path);
        return false;
    }

    // Go through each character and dump tag data + pixel data to a file
    static char output_path[512];
    struct font_character *character = (struct font_character *)(buffer_in + characters_offset);
    for(int i = 0; i < characters_count; i++) {
        snprintf(output_path, sizeof(output_path), "%s/%u.bin", output_dir, byteswap16(character->character));
        size_t pixels_size = calculate_pixels_size(byteswap16(character->bitmap_width), byteswap16(character->bitmap_height));
        size_t pixels_offset = pixel_data_offset + byteswap32(character->pixels_offset);
        if(pixels_size > pixel_data_size) {
            fprintf(stderr, "Pixel data for character %d is out of bounds\n", i);
            return false;
        }

        // Copy file data to save
        uint8_t *buffer_out = calloc(sizeof(struct font_character) + pixels_size, 1);
        size_t buffer_out_size = sizeof(struct font_character) + pixels_size;
        struct font_character *character_out = (struct font_character *)buffer_out;
        *character_out = *character;
        memcpy(buffer_out + sizeof(struct font_character), buffer_in + pixels_offset, pixels_size);

        // Save file
        FILE *file_out;
        file_out = fopen(output_path, "wb");
        if(!file_out) {
            fprintf(stderr, "Could not open %s for writing\n", output_path);
            return false;
        }

        if(fwrite(buffer_out, buffer_out_size, 1, file_out) != 1) {
            fprintf(stderr, "Could not write %zu bytes to %s\n", buffer_out_size, output_path);
            return false;
        }

        fclose(file_out);
        free(buffer_out);
        character++;
    }

    free(buffer_in);
    return true;
}

static bool produce_font_tag_from_bullshit(const char *input_dir, const char *output_path) {
    DIR *d;
    struct dirent *dir;
    uint16_t character_files[UINT16_MAX];
    int character_files_count = 0;
    d = opendir(input_dir);
    if(d) {
        while((dir = readdir(d)) != NULL) {
            // Exclude "." and ".."
            if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
                int file_value;
                if(!sscanf(dir->d_name, "%d.bin", &file_value) == 1) {
                    fprintf(stderr, "%s is not named with format <character number>.bin\n", dir->d_name);
                    return false;
                }

                if(file_value > UINT16_MAX || file_value < 0) {
                    fprintf(stderr, "%s is out of bounds to be a valid font character\n", dir->d_name);
                    return false;
                }

                character_files[character_files_count] = file_value;
                character_files_count++;
            }
        }
        closedir(d);
    }
    else {
        fprintf(stderr, "Could not open directory %s\n", input_dir);
        return false;
    }

    // Font characters should be stored from lowest to highest
    qsort(character_files, character_files_count, sizeof(uint16_t), compare_characters);

    size_t new_pixel_data_size = 0;
    size_t pixel_data_buffer_size = 32 * 1024 * 1024;
    uint8_t *pixel_data_buffer = calloc(pixel_data_buffer_size, 1);
    struct font_character *characters_buffer = calloc(sizeof(struct font_character), UINT16_MAX);

    if(!pixel_data_buffer || !characters_buffer) {
        fprintf(stderr, "Could not allocate pixel and character buffers\n");
        return false;
    }

    // Get all of our character and pixel data
    struct font_character *current_character = characters_buffer;
    static char path_buffer[512];
    int16_t max_ascending_height = 1;
    int16_t max_descending_height = 1;
    for(int i = 0; i < character_files_count; i++) {
        // Open
        FILE *file_in = nullptr;
        size_t file_in_size = 0;
        snprintf(path_buffer, sizeof(path_buffer), "%s/%d.bin", input_dir, character_files[i]);
        file_in = fopen(path_buffer, "rb");
        if(!file_in) {
            fprintf(stderr, "Failed to open %s.\n", path_buffer);
            return false;
        }

        // Get size
        fseek(file_in, 0, SEEK_END);
        file_in_size = ftell(file_in);
        fseek(file_in, 0, SEEK_SET);

        if(file_in_size < sizeof(struct font_character)) {
            fprintf(stderr, "%s is too small to be a font character.\n", path_buffer);
            return false;
        }

        // Read character struct
        if(fread(current_character, sizeof(struct font_character), 1, file_in) != 1) {
            fprintf(stderr, "Could not read character data from %s.\n", path_buffer);
            return false;
        }

        // Check remaning file size matches what is expected.
        size_t pixels_size = calculate_pixels_size(byteswap16(current_character->bitmap_width), byteswap16(current_character->bitmap_height));
        if(file_in_size != sizeof(struct font_character) + pixels_size) {
            fprintf(stderr, "%s has an invalid pixel data size.\n", path_buffer);
            return false;
        }

        // Make sure the character we just loaded is set correctly
        uint16_t old_char = byteswap16(current_character->character);
        if(character_files[i] != old_char) {
            printf("%s: importing internal character %u as %u\n", path_buffer, old_char, character_files[i]);
            current_character->character = byteswap16(character_files[i]);
        }

        // Copy pixels if we have any.
        if(pixels_size != 0) {
            if(fread(pixel_data_buffer + new_pixel_data_size, pixels_size, 1, file_in) != 1) {
                fprintf(stderr, "Could not read pixels from %s.\n", path_buffer);
                return false;
            }
            new_pixel_data_size += pixels_size;
        }

        fclose(file_in);

        // Approximate
        int16_t descending_height = byteswap16(current_character->bitmap_height) - byteswap16(current_character->bitmap_origin_y);
        int16_t ascending_height = byteswap16(current_character->bitmap_height) - descending_height;
        if(ascending_height > max_ascending_height) {
            max_ascending_height = ascending_height;
        }
        if(descending_height > max_descending_height) {
            max_descending_height = descending_height;
        }

        current_character++;
    }

    // Make a tag
    size_t new_character_data_offset = sizeof(struct tag_header) + sizeof(struct font_base);
    size_t new_character_data_size = sizeof(struct font_character) * character_files_count;
    size_t new_pixel_data_offset = new_character_data_offset + new_character_data_size;
    size_t new_tag_buffer_size = new_character_data_offset + new_character_data_size + new_pixel_data_size;
    uint8_t *new_tag_buffer = calloc(new_tag_buffer_size, 1);
    if(!new_tag_buffer) {
        fprintf(stderr, "Could not allocate tag file buffer\n");
        return false;
    }

    // Setup header
    struct tag_header *new_tag_header = (struct tag_header *)new_tag_buffer;
    new_tag_header->tag_group = byteswap32(FONT_SIGNATURE);
    new_tag_header->checksum = 0xFFFFFFFF; // FIXME Calculate this
    new_tag_header->offset = byteswap32(sizeof(struct tag_header));
    new_tag_header->unused_index = 255;
    new_tag_header->version = byteswap16(1);
    new_tag_header->signature = byteswap32(TAG_HEADER_SIGNATURE);

    // Setup font base struct
    struct font_base *new_font_base = (struct font_base *)(new_tag_buffer + sizeof(struct tag_header));

    // Set these
    new_font_base->ascending_height = byteswap16(max_ascending_height);
    new_font_base->descending_height = byteswap16(max_descending_height);
    new_font_base->pixels.size = byteswap32(new_pixel_data_size);
    new_font_base->characters.count = byteswap32(character_files_count);

    // I could leave this, but I want the file to round-trip as if it were just made by invader-font
    for(int i = 0; i < STYLE_FONTS_COUNT; i++) {
        new_font_base->style_fonts[i].tag_group = byteswap32(FONT_SIGNATURE);
        new_font_base->style_fonts[i].index = 0xFFFFFFFF;
    }

    // Copy characters
    memcpy(new_tag_buffer + new_character_data_offset, characters_buffer, new_character_data_size);
    free(characters_buffer);

    // Copy pixel data
    memcpy(new_tag_buffer + new_pixel_data_offset, pixel_data_buffer, new_pixel_data_size);
    free(pixel_data_buffer);

    // Save file
    FILE *file_out;
    file_out = fopen(output_path, "wb");
    if(!file_out) {
        fprintf(stderr, "Could not open %s for writing\n", output_path);
        return false;
    }

    if(fwrite(new_tag_buffer, new_tag_buffer_size, 1, file_out) != 1) {
        fprintf(stderr, "Could not write %zu bytes to %s\n", new_tag_buffer_size, output_path);
        return false;
    }

    fclose(file_out);
    free(new_tag_buffer);
    return true;
}

int main(int argc, const char **argv) {
    char *executable_path = strdup(argv[0]);
    if(!executable_path) {
        return 1;
    }
    char *executable = basename(executable_path);
    if(argc != 4) {
        error_usage:
        printf("Usage: %s <split/join> <input> <output>\n",executable);
        return 1;
    }

    const char *command = argv[1];
    const char *input = argv[2];
    const char *output = argv[3];

    bool success = false;

    // Check what mode
    if(strcmp(command, "split") == 0) {
        success = split_font_tag(input, output);
    }
    else if(strcmp(command, "join") == 0) {
        success = produce_font_tag_from_bullshit(input, output);
    }
    else {
        goto error_usage;
    }

    return success ? 0 : 1;
}
