// Font Slicer, by Aerocatia

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef _WIN32
#define MKDIR(path, mode) mkdir(path)
#else
#define MKDIR(path, mode) mkdir(path, mode)
#endif

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
	uint32_t size; // never set 😭
	char pad2[4];
	uint16_t version; // version of the tag
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
	uint32_t file_offset; // not in loose tags
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

struct font_character_table_entry {
	uint16_t character_index;
};
static_assert(sizeof(struct font_character_table_entry) == 2);

struct font_character_tables_entry {
	struct tag_reflexive table;
};
static_assert(sizeof(struct font_character_tables_entry) == 12);

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

/*
 *  CRC code COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 */

static uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static uint32_t crc32(uint32_t crc, const void *buf, size_t size) {
    const uint8_t *p;
    p = buf;
    while(size--) {
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }

    return crc;
}

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
        fprintf(stderr, "Failed to open %s\n", tag_path);
        return false;
    }

    // Get size and check if big enough
    fseek(file_in, 0, SEEK_END);
    buffer_in_size = ftell(file_in);
    fseek(file_in, 0, SEEK_SET);
    if(buffer_in_size < sizeof(struct tag_header) + sizeof(struct font_base)) {
        fprintf(stderr, "%s is too small to be a valid font tag\n", tag_path);
        return false;
    }

    // Read into buffer
    buffer_in = malloc(buffer_in_size);
    if(!buffer_in) {
        fprintf(stderr, "Could not allocate %zu bytes for input buffer", buffer_in_size);
        return false;
    }

    if(fread(buffer_in, buffer_in_size, 1, file_in) != 1) {
        fprintf(stderr, "Could not read from %s\n", tag_path);
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
        fprintf(stderr, "%s has no characters to split\n", tag_path);
        return false;
    }

    // do we have too many characters?
    if(characters_count > UINT16_MAX) {
        fprintf(stderr, "%s has too many characters to be a valid font tag\n", tag_path);
        return false;
    }

    // do we have pixel data?
    size_t pixel_data_size = byteswap32(font->pixels.size);
    if(pixel_data_size == 0) {
        fprintf(stderr, "%s has no pixel data\n", tag_path);
        return false;
    }

    // Start going through the rest of the tag data
    size_t font_tag_cursor = sizeof(struct tag_header) + sizeof(struct font_base);

    // Add size of character tables if they exist
    uint32_t character_tables_count = byteswap32(font->character_tables.count);
    if(character_tables_count != 0) {
        size_t character_tables_size = character_tables_count * sizeof(struct font_character_tables_entry);
        if(buffer_in_size < font_tag_cursor + character_tables_size) {
            fprintf(stderr, "%s has character tables that are out of bounds\n", tag_path);
            return false;
        }
        struct font_character_tables_entry *character_tables = (struct font_character_tables_entry *)(buffer_in + font_tag_cursor);
        for(int i = 0; i < character_tables_count; i++) {
            font_tag_cursor += byteswap32(character_tables->table.count) * sizeof(struct font_character_table_entry);
            character_tables++;
        }
        font_tag_cursor += character_tables_size;
    }

    // Add up any paths from the references
    for(int i = 0; i < STYLE_FONTS_COUNT; i++) {
        uint32_t name_legnth = byteswap32(font->style_fonts[i].name_length);
        if(name_legnth != 0) {
            font_tag_cursor += name_legnth + 1;
        }
    }

    // Offset to character data
    size_t characters_offset = font_tag_cursor;

    // Offset to pixel data
    size_t pixel_data_offset = font_tag_cursor + characters_count * sizeof(struct font_character);
    if(buffer_in_size != pixel_data_offset + pixel_data_size) {
        fprintf(stderr, "%s is fucked\n", tag_path);
        return false;
    }

    // Check output directory exists, make it if not (parent must exist)
    struct stat st = {0};
    if(stat(output_dir, &st) == -1) {
        if(MKDIR(output_dir, 0777) == -1) {
            fprintf(stderr, "Error creating directory %s\n", output_dir);
            return false;
        }
    }
    else if(!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Output %s is not a valid directory path\n", output_dir);
        return false;
    }

    // Output buffer
    size_t buffer_out_size = 1 * 1024 * 1024;
    uint8_t *buffer_out = malloc(buffer_out_size);
    if(!buffer_out) {
        fprintf(stderr, "Could not allocate %zu bytes for output buffer", buffer_out_size);
        return false;
    }

    // Go through each character and dump tag data + pixel data to a file
    static char output_path[512];
    static bool seen[UINT16_MAX] = {false};
    struct font_character *character = (struct font_character *)(buffer_in + characters_offset);
    for(int i = 0; i < characters_count; i++) {
        uint16_t character_type = byteswap16(character->character);
        if(seen[character_type]) {
            fprintf(stderr, "Warning: skipped extracting duplicate character %u at index %d\n", character_type, i);
            continue;
        }

        seen[character_type] = true;
        snprintf(output_path, sizeof(output_path), "%s/%u.bin", output_dir, character_type);
        size_t pixels_size = calculate_pixels_size(byteswap16(character->bitmap_width), byteswap16(character->bitmap_height));
        size_t pixels_offset = pixel_data_offset + byteswap32(character->pixels_offset);
        if(pixels_size > pixel_data_size) {
            fprintf(stderr, "Pixel data for character %d is out of bounds\n", i);
            return false;
        }

        // Copy file data to save
        size_t character_file_size = sizeof(struct font_character) + pixels_size;
        if(character_file_size > buffer_out_size) {
            fprintf(stderr, "Character %d is too large for output buffer\n", i);
            return false;
        }

        memset(buffer_out, 0, character_file_size);
        struct font_character *character_out = (struct font_character *)buffer_out;
        *character_out = *character;
        if(pixels_size != 0) {
            memcpy(buffer_out + sizeof(struct font_character), buffer_in + pixels_offset, pixels_size);
        }
        else {
            fprintf(stderr, "Warning: character %d has no pixel data\n", i);
        }

        // Clear stale pixel data offset
        character_out->pixels_offset = 0;

        // Save file
        FILE *file_out;
        file_out = fopen(output_path, "wb");
        if(!file_out) {
            fprintf(stderr, "Could not open %s for writing\n", output_path);
            return false;
        }

        if(fwrite(buffer_out, character_file_size, 1, file_out) != 1) {
            fprintf(stderr, "Could not write %zu bytes to %s\n", character_file_size, output_path);
            return false;
        }

        fclose(file_out);
        character++;
    }

    free(buffer_in);
    free(buffer_out);
    return true;
}

static bool produce_font_tag_from_bullshit(const char *input_dir, const char *output_path) {
    DIR *d;
    struct dirent *dir;
    static uint16_t character_files[UINT16_MAX];
    int character_files_count = 0;
    d = opendir(input_dir);
    if(d) {
        while((dir = readdir(d)) != nullptr) {
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

    // Nothing to do if there are no characters
    if(character_files_count == 0) {
        fprintf(stderr, "No valid font characters were found in %s\n", input_dir);
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
            fprintf(stderr, "Failed to open %s\n", path_buffer);
            return false;
        }

        // Get size
        fseek(file_in, 0, SEEK_END);
        file_in_size = ftell(file_in);
        fseek(file_in, 0, SEEK_SET);

        if(file_in_size < sizeof(struct font_character)) {
            fprintf(stderr, "%s is too small to be a font character\n", path_buffer);
            return false;
        }

        // Read character struct
        if(fread(current_character, sizeof(struct font_character), 1, file_in) != 1) {
            fprintf(stderr, "Could not read character data from %s\n", path_buffer);
            return false;
        }

        // Check remaning file size matches what is expected
        size_t pixels_size = calculate_pixels_size(byteswap16(current_character->bitmap_width), byteswap16(current_character->bitmap_height));
        if(file_in_size != sizeof(struct font_character) + pixels_size) {
            fprintf(stderr, "pixel data size for %s is invalid\n", path_buffer);
            return false;
        }

        // Will we explode?
        if(new_pixel_data_size + pixels_size > pixel_data_buffer_size) {
            fprintf(stderr, "Ran out of space for pixel data (>32MiB). Goodbye.\n");
            return false;
        }

        // Make sure the character we just loaded is set correctly
        uint16_t old_char = byteswap16(current_character->character);
        if(character_files[i] != old_char) {
            printf("%s: importing internal character %u as %u\n", path_buffer, old_char, character_files[i]);
            current_character->character = byteswap16(character_files[i]);
        }

        // This is always set to the current position, even if there are no pixels
        current_character->pixels_offset = byteswap32(new_pixel_data_size);

        // Copy pixels if we have any.
        if(pixels_size != 0) {
            if(fread(pixel_data_buffer + new_pixel_data_size, pixels_size, 1, file_in) != 1) {
                fprintf(stderr, "Could not read pixels from %s\n", path_buffer);
                return false;
            }

            new_pixel_data_size += pixels_size;
        }
        else {
            fprintf(stderr, "Warning: character %u has no pixel data\n", character_files[i]);
        }

        fclose(file_in);

        // Approximate. Will match invader-font, but tool.exe uses values directly from Windows
        // These can be adjusted after the fact anyway
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

    // Calculate tag checksum
    new_tag_header->checksum = byteswap32(crc32(0xFFFFFFFF, new_tag_buffer + sizeof(struct tag_header), new_tag_buffer_size - sizeof(struct tag_header)));

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
        printf("Usage: %s <command> <command args>\nCommands:\n    split <input tag> <output dir>\n    join  <input dir> <new tag path>\n",executable);
        return 1;
    }

    const char *command = argv[1];
    const char *input = argv[2];
    const char *output = argv[3];

    bool success = false;

    // Check what command
    if(strcmp(command, "split") == 0) {
        success = split_font_tag(input, output);
    }
    else if(strcmp(command, "join") == 0) {
        success = produce_font_tag_from_bullshit(input, output);
    }
    else {
        goto error_usage;
    }

    free(executable_path);

    return success ? 0 : 1;
}
