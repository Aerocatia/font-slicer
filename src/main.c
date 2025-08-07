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
	uint8_t unused_index; // always 255
	char pad3;
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

uint16_t byteswap16(uint16_t value) {
    return (value << 8) | (value >> 8);
}

uint32_t byteswap32(uint32_t value) {
    return ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | ((value & 0xFF0000) >> 8) | (value >> 24);
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

    // Allocate
    buffer_in = malloc(buffer_in_size);
    if(!buffer_in) {
        fprintf(stderr, "Could not allocate %zu bytes.", buffer_in_size);
        return false;
    }

    // Read
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
        int16_t width = byteswap16(character->bitmap_width);
        int16_t height = byteswap16(character->bitmap_height);
        size_t pixels_size;

        // Ask bungie
        if(width < 1 || height < 1) {
            pixels_size = 0;
        }
        else {
            pixels_size = width * height;
        }

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

    }
    else {
        goto error_usage;
    }

    return success ? 0 : 1;
}
