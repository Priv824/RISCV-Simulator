#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define MEMORY_SIZE 327680  
#define STACK_START 0x50000
#define DATA_SECTION_START 0x10000
#define MAX_STACK_SIZE 50
#define MAX_TAG_LENGTH 20
#define MAX_SETS 65536
#define MAX_ASSOCIATIVITY 16

typedef struct {
    char* Label;
    int lineNum;
} Labels;

typedef struct {
    char* instrc;
    char* opcode;
    char* funct3;
    char* funct7;
} RFormat;

typedef struct {
    char* instrc;
    char* opcode;
    char* funct3;
} IFormat;

typedef struct {
    char* instrc;
    char* opcode;
    char* funct3;
} SFormat;

typedef struct {
    char* instrc;
    char* opcode;
    char* funct3;
} BFormat;

typedef struct {
    char* instrc;
    char* opcode;
} JFormat;

typedef struct {
    char* instrc;
    char* opcode;
} UFormat;

typedef struct {
    char name[4];
    int number;
} Register;

typedef struct {
    char* instrc;
    char* rd;
    char* rs1;
    char* rs2;
    char* imm;
    int lineNum;
} Instruction;

typedef struct {
    char* data;
} Data;

typedef struct Stack {
    int line[MAX_STACK_SIZE];
    char labels[MAX_STACK_SIZE][MAX_TAG_LENGTH];
    int current_index;

} Stack;

typedef struct {
    bool valid;
    bool dirty;
    uint32_t tag;
    uint32_t replacement_data;
    uint32_t arrival_data;
    int8_t *data;
} CacheLine;

typedef struct {
    CacheLine *lines;
} CacheSet;

typedef struct {
    CacheSet *sets;
    uint32_t num_sets;
    uint32_t num_lines_per_set;
    uint32_t accesses;
    uint32_t hits;
    uint32_t misses;
} Cache;

char command[100];
Labels labels[50];
uint64_t registers[32] = {0};
int8_t memory[MEMORY_SIZE];
Instruction instructions[50];
Data dword[50];
Data word[50];
Data halfword[50];
Data byte[50];
Stack* S;
uint64_t pc = 0x0000000000000000;
uint64_t next_pc;
Cache* CACHE;
CacheLine *line_to_replace = NULL;
bool cache_enabled;
int executingLineNum = 0;
int label_line = 0;
int breakpoints[5] = {-1,-1,-1,-1,-1};
int deleted_lines_count = 0;
long long int cache_size;
long int block_size;
long int associativity;
char replacement_policy[10];
char write_policy[10];
char filename[256];

RFormat rformatTable[] = {
        {"add", "0110011", "000", "0000000"},
        {"sub", "0110011", "000", "0100000"},
        {"and", "0110011", "111", "0000000"},
        {"or",  "0110011", "110", "0000000"},
        {"xor", "0110011", "100", "0000000"},
        {"sll", "0110011", "001", "0000000"},
        {"srl", "0110011", "101", "0000000"},
        {"sra", "0110011", "101", "0100000"}
};

IFormat iformatTable[] = {
        {"lb",  "0000011", "000"},
        {"lh",  "0000011", "001"},
        {"lw",  "0000011", "010"},
        {"lbu",  "0000011", "100"},
        {"lhu",  "0000011", "101"},
        {"lwu",  "0000011", "110"},
        {"ld",  "0000011", "011"},
        {"addi", "0010011", "000"},
        {"andi", "0010011", "111"},
        {"ori",  "0010011", "110"},
        {"xori", "0010011", "100"},
        {"slli", "0010011", "001"},
        {"srli", "0010011", "101"},
        {"srai", "0010011", "101"},
        {"jalr", "1100111", "000"}
};

SFormat sformatTable[] = {
        {"sb",  "0100011", "000"},
        {"sh",  "0100011", "001"},
        {"sw",  "0100011", "010"},
        {"sd",  "0100011", "011"},
};

BFormat bformatTable[] = {
        {"beq", "1100011", "000"},
        {"bne", "1100011", "001"},
        {"blt", "1100011", "100"},
        {"bge", "1100011", "101"},
        {"bltu", "1100011", "110"},
        {"bgeu", "1100011", "111"}
};

JFormat jformatTable[] = {
        {"jal", "1101111"}
};

UFormat uformatTable[] = {
        {"lui","0110111"}
};

Register registerTable[] = {
        {"x0", 0}, {"x1", 1}, {"x2", 2}, {"x3", 3}, {"x4", 4},
        {"x5", 5}, {"x6", 6}, {"x7", 7}, {"x8", 8}, {"x9", 9},
        {"x10", 10}, {"x11", 11}, {"x12", 12}, {"x13", 13}, {"x14", 14},
        {"x15", 15}, {"x16", 16}, {"x17", 17}, {"x18", 18}, {"x19", 19},
        {"x20", 20}, {"x21", 21}, {"x22", 22}, {"x23", 23}, {"x24", 24},
        {"x25", 25}, {"x26", 26}, {"x27", 27}, {"x28", 28}, {"x29", 29},
        {"x30", 30}, {"x31", 31},
        {"zero", 0}, {"ra", 1}, {"sp", 2}, {"gp", 3}, {"tp", 4},
        {"t0", 5}, {"t1", 6}, {"t2", 7}, {"s0", 8}, {"s1", 9},
        {"a0", 10}, {"a1", 11}, {"a2", 12}, {"a3", 13}, {"a4", 14},
        {"a5", 15}, {"a6", 16}, {"a7", 17}, {"s2", 18}, {"s3", 19},
        {"s4", 20}, {"s5", 21}, {"s6", 22}, {"s7", 23}, {"s8", 24},
        {"s9", 25}, {"s10", 26}, {"s11", 27}, {"t3", 28}, {"t4", 29},
        {"t5", 30}, {"t6", 31}
};

void load_file (char* filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file\n");
        return;
    }
    printf("File Loaded Succesfully\n");
    fclose(file);

}

void parsefile(FILE *file) {
    char line[256];  // Buffer for reading each line
    int lineNum = 0; // Instruction line number counter

    // Parsing instructions
    while (lineNum < 50 && fgets(line, sizeof(line), file)) {
        if (line[0] == '.') {
            deleted_lines_count++;
            continue; // Skip lines starting with '.'
        }
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;
        char* colonPos = strchr(line, ':'); // Find colon for label-instruction separation

        // Allocate memory for each instruction's fields (if not already done)
        instructions[lineNum].instrc = calloc(100, sizeof(char));
        instructions[lineNum].rs1 = calloc(100, sizeof(char));
        instructions[lineNum].rs2 = calloc(100, sizeof(char));
        instructions[lineNum].rd = calloc(100, sizeof(char));
        instructions[lineNum].imm = calloc(100, sizeof(char));

        // Memory allocation check
        if (instructions[lineNum].instrc == NULL || instructions[lineNum].rs1 == NULL ||
            instructions[lineNum].rs2 == NULL || instructions[lineNum].rd == NULL ||
            instructions[lineNum].imm == NULL) {
            fprintf(stderr, "Memory allocation failed for instruction fields\n");
            exit(1);
        }

        if (colonPos != NULL) {
            // Split label and instruction
            char* token = strtok(line, " :\n");
            token = strtok(NULL, " \n");
            if (token != NULL) {
                strncpy(instructions[lineNum].instrc, token, 99); // Prevent buffer overflow
                instructions[lineNum].lineNum = lineNum;
            }
        } else {
            // No label; process the instruction
            char* token = strtok(line, " \n");
            if (token != NULL) {
                strcpy(instructions[lineNum].instrc, token);
                instructions[lineNum].lineNum = lineNum;
            }
        }

        // Handle R-format instructions
        for (int i = 0; i < 8; i++) {
            if (strcmp(instructions[lineNum].instrc, rformatTable[i].instrc) == 0) {
                char* rdToken = strtok(NULL, ", ");
                char* rs1Token = strtok(NULL, ", ");
                char* rs2Token = strtok(NULL, ", \n");

                if (rdToken != NULL) strcpy(instructions[lineNum].rd, rdToken);
                if (rs1Token != NULL) strcpy(instructions[lineNum].rs1, rs1Token);
                if (rs2Token != NULL) strcpy(instructions[lineNum].rs2, rs2Token);
                break;
            }
        }

        // Handle I-format instructions
        for (int i = 0; i < 7; i++) {
            if (strcmp(instructions[lineNum].instrc, iformatTable[i].instrc) == 0 || strcmp(instructions[lineNum].instrc, "jalr") == 0) {
                char* rdToken = strtok(NULL, ",() ");
                char* immToken = strtok(NULL, ",() \n");
                char* rs1Token = strtok(NULL, ",() ");

                if (rdToken != NULL) strcpy(instructions[lineNum].rd, rdToken);
                if (immToken != NULL) strcpy(instructions[lineNum].imm, immToken);
                if (rs1Token != NULL) strcpy(instructions[lineNum].rs1, rs1Token);
                break;
            }
        }

        for (int i = 7; i < 14; i++) {
            if (strcmp(instructions[lineNum].instrc, iformatTable[i].instrc) == 0) {
                char* rdToken = strtok(NULL, ", ");
                char* rs1Token = strtok(NULL, ", \n");
                char* immToken = strtok(NULL, ", ");

                if (rdToken != NULL) strcpy(instructions[lineNum].rd, rdToken);
                if (rs1Token != NULL) strcpy(instructions[lineNum].rs1, rs1Token);
                if (immToken != NULL) strcpy(instructions[lineNum].imm, immToken);
            }
        }

        // Handle S-format instructions
        for (int i = 0; i < 4; i++) {
            if (strcmp(instructions[lineNum].instrc, sformatTable[i].instrc) == 0) {
                char* rs2Token = strtok(NULL, ", ");
                char* immToken = strtok(NULL, "() ");
                char* rs1Token = strtok(NULL, " ()\n");

                if (rs2Token != NULL) strcpy(instructions[lineNum].rs2, rs2Token);
                if (immToken != NULL) strcpy(instructions[lineNum].imm, immToken);
                if (rs1Token != NULL) strcpy(instructions[lineNum].rs1, rs1Token);
            }
        }

        // Handle B-format instructions
        for (int i = 0; i < 6; i++) {
            if (strcmp(instructions[lineNum].instrc, bformatTable[i].instrc) == 0) {
                char* rs1Token = strtok(NULL, ", ");
                char* rs2Token = strtok(NULL, ", ");
                char* immToken = strtok(NULL, " ,\n");

                if (rs1Token != NULL) strcpy(instructions[lineNum].rs1, rs1Token);
                if (rs2Token != NULL) strcpy(instructions[lineNum].rs2, rs2Token);
                if (immToken != NULL) strcpy(instructions[lineNum].imm, immToken);
            }
        }

        if (strcmp(instructions[lineNum].instrc, "jal") == 0) {
            char* rdToken = strtok(NULL, ", ");
            char* immToken = strtok(NULL, " ,\n");

            if (rdToken != NULL) strcpy(instructions[lineNum].rd, rdToken);
            if (immToken != NULL) strcpy(instructions[lineNum].imm, immToken);
        }

        if (strcmp(instructions[lineNum].instrc, "lui") == 0) {
            char* rdToken = strtok(NULL, ", ");
            char* immToken = strtok(NULL, " ,\n");

            if (rdToken != NULL) strcpy(instructions[lineNum].rd, rdToken);
            if (immToken != NULL) strcpy(instructions[lineNum].imm, immToken);
        }
        lineNum++;
    }

    rewind(file); // Rewind file to parse labels

    int labelIndex = 0;
    while (labelIndex < 50 && fgets(line, sizeof(line), file)) {
        if (line[0] == '.') {
            continue; // Skip lines starting with '.'
        }

        char* colonPos = strchr(line, ':'); // Check for label
        if (colonPos != NULL) {
            labels[labelIndex].Label = calloc(100, sizeof(char));

            // Memory allocation check for labels
            if (labels[labelIndex].Label == NULL) {
                fprintf(stderr, "Memory allocation failed for labels\n");
                exit(1);
            }

            strncpy(labels[labelIndex].Label, strtok(line, ": "), 99);
            labels[labelIndex].lineNum = labelIndex;
        } else {
            labels[labelIndex].Label = NULL;
            labels[labelIndex].lineNum = labelIndex;
        }

        labelIndex++;
    }
    
    rewind(file);

    int ok = 0;
    uint64_t addr = DATA_SECTION_START;
    while (ok < 50 && fgets(line, sizeof(line), file)) {
        if (line[0] == '.') {
        char* temp = strtok(line + 1, " ");  // Skip the first character ('.')
        
        if (strcmp(temp, "data") == 0) {
            continue;  // Continue parsing for data section
        }
        else if (strcmp(temp, "text") == 0) {
            break;  // Stop when we hit the text section
        }
        else if (strcmp(temp, "dword") == 0) {
            for (int i = 0; i < 50; i++) {
                dword[i].data = calloc(100, sizeof(char));
                if (dword[i].data == NULL) {
                    fprintf(stderr, "Memory allocation failed for dword data\n");
                    exit(1);
                }
                char* token = strtok(NULL, " ,\n");
                if (token != NULL) {
                    strncpy(dword[i].data, token, 99);
                    int64_t data = strtoll(dword[i].data, NULL, 0);
                    for(int j = 0; j < 8; j++) {
                        //printf("%ld at dword\n", data);
                        int8_t byte_value = (data >> (j * 8)) & 0xFF;  // Extract byte
                        memory[addr] = (int8_t)byte_value;
                        addr++;
                    }
                } else {
                    break;  // Stop if there are no more tokens
                }
            }
        }
        else if (strcmp(temp, "word") == 0) {
            for (int i = 0; i < 50; i++) {
                word[i].data = calloc(100, sizeof(char));
                if (word[i].data == NULL) {
                    fprintf(stderr, "Memory allocation failed for word data\n");
                    exit(1);
                }
                char* token = strtok(NULL, " ,\n");
                if (token != NULL) {
                    strncpy(word[i].data, token, 99);
                     int64_t data = strtoll(word[i].data, NULL, 0);
                    for(int j = 0; j < 4; j++) {
                        //printf("%ld\n", data);
                        uint8_t byte_value = (data >> (j * 8)) & 0xFF;  // Extract byte
                        memory[addr] = (int8_t)byte_value;
                        addr++;
                    }
                } else {
                    break;
                }
            }
        }
        else if (strcmp(temp, "half") == 0) {
            for (int i = 0; i < 50; i++) {
                halfword[i].data = calloc(100, sizeof(char));
                if (halfword[i].data == NULL) {
                    fprintf(stderr, "Memory allocation failed for halfword data\n");
                    exit(1);
                }
                char* token = strtok(NULL, " ,\n");
                if (token != NULL) {
                    strncpy(halfword[i].data, token, 99);
                     int64_t data = strtoll(halfword[i].data, NULL, 0);
                    for(int j = 0; j < 2; j++) {
                        //printf("%ld\n", data);
                        uint8_t byte_value = (data >> (j * 8)) & 0xFF;  // Extract byte
                        memory[addr] = (int8_t)byte_value;
                        addr++;
                    }
                } else {
                    break;
                }
            }
        }
        else if (strcmp(temp, "byte") == 0) {
            for (int i = 0; i < 50; i++) {
                byte[i].data = calloc(100, sizeof(char));
                if (byte[i].data == NULL) {
                    fprintf(stderr, "Memory allocation failed for byte data\n");
                    exit(1);
                }
                char* token = strtok(NULL, " ,\n");
                if (token != NULL) {
                    strncpy(byte[i].data, token, 99);
                    int64_t data = strtoll(byte[i].data, NULL, 0);
                        //printf("%ld\n", data);
                        uint8_t byte_value = (data) & 0xFF;  // Extract byte
                        memory[addr] = (int8_t)byte_value;
                        addr++;
                } else {
                    break;
                }
            }
        }
        ok++;
    }
    }

    // for (int i = 0; i < 50; i++) {
    //     if (labels[i].Label != NULL) {
    //         printf("Label %d : %s\n", i, labels[i].Label);
    //     }
    // }
    // for (int i = 0; i < 50; i++) {
    //     if (instructions[i].instrc != NULL) {
    //         printf("Instruction %d : %s rd: %s rs1: %s rs2: %s imm: %s\n",
    //                i, instructions[i].instrc, instructions[i].rd, instructions[i].rs1, instructions[i].rs2, instructions[i].imm);
    //     }
    // }
    // for (int i = 0; i < 50; i++) {
    //     if (dword[i].data != NULL) {
    //         printf("dword %d %s\n", i,dword[i].data);
    //     }
    // }
    // for (int i = 0; i < 50; i++) {
    //     if (word[i].data != NULL) {
    //         printf("word %d %s\n", i,word[i].data);
    //     }
    // }
    // for (int i = 0; i < 50; i++) {
    //     if (halfword[i].data != NULL) {
    //         printf("halfword %d %s\n", i,halfword[i].data);
    //     }
    // }
    // for (int i = 0; i < 50; i++) {
    //     if (byte[i].data != NULL) {
    //         printf("byte %d %s\n", i,byte[i].data);
    //     }
    // }
}

void exit_program() {
    printf("Exited the simulator\n");
    exit(0);
}

void read_config(FILE* config) {
    char line[256];
    int count = 0; 

    while (fgets(line, 256, config) != NULL && count < 5) {
        switch (count) {
            case 0:
                cache_size = strtoll(line, NULL, 0);
                break;
            case 1:
                block_size = strtol(line, NULL, 0);
                break;
            case 2:
                associativity = strtol(line, NULL, 0);
                break;
            case 3:
                strncpy(replacement_policy, line, sizeof(replacement_policy) - 1);
                replacement_policy[sizeof(replacement_policy) - 1] = '\0'; // Ensure null termination
                break;
            case 4:
                strncpy(write_policy, line, sizeof(write_policy) - 1);
                write_policy[sizeof(write_policy) - 1] = '\0';
                break;
        }
        count++;
    }
}

Cache *initialize_cache() {
    uint32_t total_blocks = cache_size / block_size;
    uint32_t num_sets = total_blocks / associativity;

    Cache *cache = (Cache *)malloc(sizeof(Cache));
    if (cache == NULL) return NULL;
    cache->num_sets = num_sets;
    cache->num_lines_per_set = associativity;
    cache->accesses = cache->hits = cache->misses = 0;

    cache->sets = (CacheSet *)malloc(num_sets * sizeof(CacheSet));
    if(cache->sets == NULL) return NULL;
    for (uint32_t i = 0; i < num_sets; i++) {
        cache->sets[i].lines = (CacheLine *)malloc(associativity * sizeof(CacheLine));
        if(cache->sets[i].lines == NULL) return NULL;
        for (uint32_t j = 0; j < associativity; j++) {
            cache->sets[i].lines[j].valid = false;
            cache->sets[i].lines[j].dirty = false;
            cache->sets[i].lines[j].replacement_data = 0;
            cache->sets[i].lines[j].data = (int8_t *)malloc(block_size * sizeof(uint8_t));
            if(cache->sets[i].lines[j].data == NULL) return NULL;
            memset(cache->sets[i].lines[j].data, 0, block_size); // Initialize data to zero
        }
    }
    return cache;
}

void log_access_cache(Cache *cache, const char *access_type, uint64_t address, bool hit, bool dirty, const char *filename) {
    char output_file_name[256];
    
    strncpy(output_file_name, filename, sizeof(output_file_name) - 1);
    output_file_name[sizeof(output_file_name) - 1] = '\0';  // Ensure null-termination
    
    char *dot_pos = strchr(output_file_name, '.');
    if (dot_pos != NULL) {
        *dot_pos = '\0';
    }
    strncat(output_file_name, ".output", sizeof(output_file_name) - strlen(output_file_name) - 1);

    FILE *output_file = fopen(output_file_name, "a");
    if (output_file == NULL) {
        fprintf(stderr, "Error opening file: %s\n", output_file_name);
        return;  
    }

    uint32_t block_offset = address % block_size;
    uint32_t index = (address / block_size) % cache->num_sets;
    uint32_t tag = address / (block_size * cache->num_sets);

    fprintf(output_file, "%s: Address: 0x%05lx, Set: 0x%02x, %s, Tag: 0x%x, %s\n",
            access_type, address & 0xFFFFF, index, hit ? "Hit" : "Miss", tag, dirty ? "Dirty" : "Clean");

    fclose(output_file);
}

void access_cache(Cache *cache, uint64_t address, const char *access_type) {
    address = address & 0xFFFFF;
    uint32_t block_offset = address % block_size;
    uint32_t index = (address / block_size) % cache->num_sets;
    uint32_t tag = address / (block_size * cache->num_sets);

    CacheSet *set = &cache->sets[index];
    bool hit = false;

    for (uint32_t i = 0; i < cache->num_lines_per_set; i++) {
        CacheLine *line = &set->lines[i];
        if (line->valid && line->tag == tag) {
            hit = true;
            cache->hits++;
            line->replacement_data = cache->accesses;
            if (strcmp(access_type, "W") == 0) {
                if (strcmp(write_policy, "WT") == 0) {
                    uint64_t block_address = (tag * block_size * cache->num_sets) + (index * block_size);
                    block_address = block_address & 0xFFFFF;
                    for (size_t i = 0; i < block_size; i++) {
                       cache->sets[index].lines[i].data[i] =  memory[block_address + i];  // Write the whole block
                    }
                    log_access_cache(cache, access_type, address, hit, false, filename);
                }
                else if (strcmp(write_policy, "WB") == 0) {
                    line->dirty = true;
                    uint64_t block_address = (tag * block_size * cache->num_sets) + (index * block_size);
                    block_address = block_address & 0xFFFFF;
                    CacheLine temp_line; 
                    for (size_t i = 0; i < block_size; i++) {
                        temp_line.data[i] = cache->sets[index].lines[i].data[i];
                        cache->sets[index].lines[i].data[i] =  memory[block_address + i];  // Change only in the cache with the correct values
                    }
                    for (size_t i = 0; i < block_size; i++) {
                        memory[block_address + i] = temp_line.data[i];  // Invalidating the memory
                    }
                    log_access_cache(cache, access_type, address, hit, true, filename);
                }
            } 
            else if (strcmp(access_type, "R") == 0) {
                // Cache hit read only nothing to do
                log_access_cache(cache, access_type, address, hit, false, filename);
            }
        }
        break;
    }
    if (!hit) {
        cache->misses++;
        int eviction_index = -1;
        bool free_line = false;

        // Look for an empty line first
        for (uint32_t i = 0; i < cache->num_lines_per_set; i++) {
            if (!set->lines[i].valid) {
                eviction_index = i;
                line_to_replace = &set->lines[eviction_index];
                free_line = true;
                break;
            }
        }
        // If no empty line is found, apply the replacement policy
        if (line_to_replace == NULL) {
            if (strcmp(replacement_policy, "LRU") == 0) {
                eviction_index = 0;
                // Find the least recently used line
                for (uint32_t i = 1; i < cache->num_lines_per_set; i++) {
                    if (set->lines[i].replacement_data < line_to_replace->replacement_data) {
                        eviction_index = i;
                    }
                }
            } 
            else if (strcmp(replacement_policy, "RANDOM") == 0) {
                eviction_index = rand() % cache->num_lines_per_set;
            }
            else if (strcmp(replacement_policy, "FIFO") == 0) {
                // Find the line which came first
                for (uint32_t i = 1; i < cache->num_lines_per_set; i++) {
                    if (set->lines[i].arrival_data < line_to_replace->arrival_data) {
                        eviction_index = i;
                    }
                }
            }
        }

        line_to_replace = &set->lines[eviction_index];

        // Step 3: If we are replacing a valid line, handle write-back if necessary
        if(strcmp(access_type, "W") == 0 && !free_line) {
            if (line_to_replace->valid && line_to_replace->dirty && strcmp(write_policy, "WB") == 0) {
                uint64_t block_address = (line_to_replace->tag * block_size * cache->num_sets) + (index * block_size);
                block_address = block_address & 0xFFFFF;
                for (size_t i = 0; i < block_size; i++) {
                    memory[block_address + i] = line_to_replace->data[i];  // Write back the entire block of data
                }
                line_to_replace->dirty = true;
                line_to_replace->valid = true;
                line_to_replace->tag = tag;
                line_to_replace->replacement_data = cache->accesses;
                line_to_replace->arrival_data = cache->accesses;
                // Load data from memory to cache line
                uint64_t block_address2 = (tag * block_size * cache->num_sets) + (index * block_size);
                block_address2 = block_address2 & 0xFFFFF;
                CacheLine temp_line; 
                for (size_t i = 0; i < block_size; i++) {
                    temp_line.data[i] = line_to_replace->data[i];
                    line_to_replace->data[i] = memory[block_address2 + i];
                }
                for (size_t i = 0; i < block_size; i++) {
                    memory[block_address + i] = temp_line.data[i];  // Invalidating memory
                }
                log_access_cache(cache, access_type, address, hit, line_to_replace->dirty, filename);
            }
            else if (line_to_replace->valid && line_to_replace->dirty && strcmp(write_policy, "WT") == 0) {
                // Do nothing, as we are using write-through policy without allocate
                log_access_cache(cache, access_type, address, hit, line_to_replace->dirty, filename);
            }
        }
        // Step 4: Bring the new block into the cache when there is an available space in the cache
        if(free_line) {
            if(strcmp(access_type, "W") == 0) {
                if(strcmp(write_policy, "WT") == 0) {
                    line_to_replace->dirty =  false;
                    line_to_replace->valid = false;
                    line_to_replace->tag = tag;
                    log_access_cache(cache, access_type, address, hit, line_to_replace->dirty, filename);
                }
                else if (strcmp(write_policy, "WB") == 0) {
                    line_to_replace->dirty = true;
                    line_to_replace->valid = true;
                    line_to_replace->tag = tag;
                    line_to_replace->replacement_data = cache->accesses;
                    line_to_replace->arrival_data = cache->accesses;
                    // Load data from memory to cache line
                    CacheLine temp_line; 
                    uint64_t block_address = (tag * block_size * cache->num_sets) + (index * block_size);
                    block_address = block_address & 0xFFFFF;
                    for (size_t i = 0; i < block_size; i++) {
                        temp_line.data[i] = line_to_replace->data[i];
                        line_to_replace->data[i] = memory[block_address + i];
                    }
                    for (size_t i = 0; i < block_size; i++) {
                        memory[block_address + i] = temp_line.data[i];  // Invalidating memory
                    }
                    log_access_cache(cache, access_type, address, hit, line_to_replace->dirty, filename);
                }
            }
            else if (strcmp(access_type, "R") == 0) {
                line_to_replace->valid = true;
                line_to_replace->tag = tag;
                line_to_replace->replacement_data = cache->accesses;
                line_to_replace->arrival_data = cache->accesses;
                // Load data from memory to cache line
                uint64_t block_address = (tag * block_size * cache->num_sets) + (index * block_size);
                // block_address = block_address & 0xFFFFF;
                for (size_t i = 0; i < block_size; i++) {
                    line_to_replace->data[i] = memory[block_address + i];
                }
                log_access_cache(cache, access_type, address, hit, line_to_replace->dirty, filename);
            }
        }
    }
    cache->accesses++;
}

void cache_sim_stats(Cache *cache) {
    printf("D-cache statistics: Accesses=%d, Hit=%d, Miss=%d, Hit Rate=%.2f\n",
           cache->accesses, cache->hits, cache->misses, (float)cache->hits / cache->accesses);
}

void cache_sim_invalidate(Cache *cache) {
    for (uint32_t i = 0; i < cache->num_sets; i++) {
        for (uint32_t j = 0; j < cache->num_lines_per_set; j++) {
            cache->sets[i].lines[j].valid = false;
            cache->sets[i].lines[j].dirty = false;
        }
    }
}

void cache_sim_dump(Cache *cache, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for writing\n", filename);
        return;
    }

    for (uint32_t i = 0; i < cache->num_sets; i++) {
        for (uint32_t j = 0; j < cache->num_lines_per_set; j++) {
            CacheLine *line = &cache->sets[i].lines[j];
            if (line->valid) {
                fprintf(file, "Set: 0x%02x, Tag: 0x%03x, %s\n", i, line->tag, line->dirty ? "Dirty" : "Clean");
            }
        }
    }
    fclose(file);
}

Stack* createEmptyStack() {
    Stack* S = (Stack*)malloc(sizeof(Stack));
    S->current_index = 0;
    S->line[0] = 0;
    strcpy(S->labels[0],"main");
    return S;
}

void push(Stack* S, char* label, int new_line) {
    if(label != NULL) {
        S->line[S->current_index] = new_line;
        S->current_index++;
        strcpy(S->labels[S->current_index],label);
    }
    S->line[S->current_index] = new_line;
}

void pop(Stack *S) {
    S->current_index--;
}

void show_stack(Stack* S){

    if(S->current_index == -1 || instructions[pc/4].instrc == NULL){
        printf("Empty Call Stack: Execution complete\n");
    }
    else{
        printf("Call Stack:\n");
        for(int i = 0; i<=S->current_index; i++){
            printf("%s:%d\n",S->labels[i],S->line[i]);
        }
    }
}

uint64_t load_memory(uint64_t address, int size, int unsigned_flag) {
    uint64_t value = 0;

    if (size == 1) {
        value = memory[address];
        if (!unsigned_flag) {
            return (value & 0x80) ? value - 0x100 : value;
        }
        return value;
    } else if (size == 2) {
        value = memory[address] | (memory[address + 1] << 8);
        if (!unsigned_flag) {
            return (value & 0x8000) ? value - 0x10000 : value;
        }
        return value;
    } else if (size == 4) {
        value = memory[address] |
                (memory[address + 1] << 8) |
                (memory[address + 2] << 16) |
                (memory[address + 3] << 24);
        if (!unsigned_flag) {
            return (value & 0x80000000) ? value - 0x100000000 : value;
        }
        return value;
    } else if (size == 8) {
        value = memory[address] |
                ((uint64_t)memory[address + 1] << 8) |
                ((uint64_t)memory[address + 2] << 16) |
                ((uint64_t)memory[address + 3] << 24) |
                ((uint64_t)memory[address + 4] << 32) |
                ((uint64_t)memory[address + 5] << 40) |
                ((uint64_t)memory[address + 6] << 48) |
                ((uint64_t)memory[address + 7] << 56);
        return value;
    } 
}

void store_memory(uint64_t address, uint64_t value, int size) {

    if (size == 1) {
        memory[address] = value & 0xFF;
    } else if (size == 2) {
        memory[address] = value & 0xFF;
        memory[address + 1] = (value >> 8) & 0xFF;
    } else if (size == 4) {
        memory[address] = value & 0xFF;
        memory[address + 1] = (value >> 8) & 0xFF;
        memory[address + 2] = (value >> 16) & 0xFF;
        memory[address + 3] = (value >> 24) & 0xFF;
    } else if (size == 8) {
        memory[address] = value & 0xFF;
        memory[address + 1] = (value >> 8) & 0xFF;
        memory[address + 2] = (value >> 16) & 0xFF;
        memory[address + 3] = (value >> 24) & 0xFF;
        memory[address + 4] = (value >> 32) & 0xFF;
        memory[address + 5] = (value >> 40) & 0xFF;
        memory[address + 6] = (value >> 48) & 0xFF;
        memory[address + 7] = (value >> 56) & 0xFF;
    }
}

int string_to_register(const char *reg) {
    for (int i = 0; i < 64; i++) {
        if (strcmp(reg, registerTable[i].name) == 0) {
            return registerTable[i].number;
        }
    }
}

int string_to_immediate(const char* imm) {
    return atoi(imm);
}

bool is_breakpoint_set(int line) {
    if (breakpoints[0] == line) {
        return true;
    }
    else if (breakpoints[1] == line) {
        return true;
    }
    else if (breakpoints[2] == line) {
        return true;
    }
    else if (breakpoints[3] == line) {
        return true;
    }
    else if (breakpoints[4] == line) {
        return true;
    }
    else {
        return false;
    }
}

void run_program(Instruction instructions[50]) {
    while (1) {
        //printf("Entered run\n");
        if (pc / 4 >= 50) {
            printf("No lines to execute\n");
            S->current_index = -1;
            break;
        }


        Instruction instr = instructions[pc / 4];
        if (instr.instrc == NULL) {
            S->current_index = -1;
            break;
        }
        int rd = string_to_register(instructions[pc / 4].rd);
        int rs1 = string_to_register(instructions[pc / 4].rs1);
        int rs2 = string_to_register(instructions[pc / 4].rs2);
        int imm = string_to_immediate(instructions[pc / 4].imm);

        next_pc = pc + 4;

        if (is_breakpoint_set(pc/4 + 1 + deleted_lines_count)) {
            printf("Execution stopped at breakpoint\n");
            break;
        }

        if (strcmp(instr.instrc, "add") == 0) {
            registers[rd] = registers[rs1] + registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "sub") == 0) {
            registers[rd] = registers[rs1] - registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "and") == 0) {
            registers[rd] = registers[rs1] & registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "or") == 0) {
            registers[rd] = registers[rs1] | registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "xor") == 0) {
            registers[rd] = registers[rs1] ^ registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "sll") == 0) {
            registers[rd] = registers[rs1] << (registers[rs2] & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "srl") == 0) {
            registers[rd] = ((uint64_t)registers[rs1]) >> (registers[rs2] & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "sra") == 0) {
            registers[rd] = ((int64_t)registers[rs1]) >> (registers[rs2] & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        }
        else if (strcmp(instr.instrc, "addi") == 0) {
            registers[rd] = registers[rs1] + imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "andi") == 0) {
            registers[rd] = registers[rs1] & imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "ori") == 0) {
            registers[rd] = registers[rs1] | imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "xori") == 0) {
            registers[rd] = registers[rs1] ^ imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "slli") == 0) {
            registers[rd] = registers[rs1] << (imm & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "srli") == 0) {
            registers[rd] = ((uint64_t)registers[rs1]) >> (imm & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "srai") == 0) {
            registers[rd] = ((int64_t)registers[rs1]) >> (imm & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        }
        else if (strcmp(instr.instrc, "ld") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 8, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lw") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 4, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lh") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 2, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lb") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 1, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lwu") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 4, 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lhu") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 2, 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lbu") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 1, 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        }
        else if (strcmp(instr.instrc, "sd") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 8);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        } else if (strcmp(instr.instrc, "sw") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 4);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        } else if (strcmp(instr.instrc, "sh") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 2);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        } else if (strcmp(instr.instrc, "sb") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        }
        else if (strcmp(instr.instrc, "beq") == 0) {
            if (registers[rs1] == registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bne") == 0) {
            if (registers[rs1] != registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "blt") == 0) {
            if ((int64_t)registers[rs1] < (int64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bge") == 0) {
            if ((int64_t)registers[rs1] >= (int64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bltu") == 0) {
            if ((uint64_t)registers[rs1] < (uint64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bgeu") == 0) {
            if ((uint64_t)registers[rs1] >= (uint64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        }
        else if (strcmp(instr.instrc, "jal") == 0) {
            registers[rd] = pc + 4;
            for (int i = 0; i < 50; i++) {
                if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                    label_line = labels[i].lineNum;
                }
            }
            imm = (label_line-labels[pc/4].lineNum)*4;
            next_pc = pc + imm;
            push(S,labels[label_line].Label,pc/4 + 1);
            //printf("NExt pc 0x%08lx\n",next_pc);
            printf("Executed %s %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, pc);

        } else if (strcmp(instr.instrc, "jalr") == 0) {
            registers[rd] = pc + 4;
            next_pc = (registers[rs1] + imm);
            //printf("Next PC 0x%08lx\n",next_pc);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            pop(S);
        }
        else if (strcmp(instr.instrc, "lui") == 0) {
            registers[rd] = imm << 12;
            printf("Executed: %s %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, pc);
        }
        //else {printf("hi\n");}
        if (strcmp(instr.instrc, "jalr") != 0) push(S,NULL,pc/4 +1);
        pc = next_pc;
        executingLineNum++;
        registers[0] = 0;
        //printf("PC has been updated 0x%08lx\n",pc);
        //printf("%d execution\n",executingLineNum);
    }
    if (cache_enabled) {
    cache_sim_stats(CACHE);
    }
}

void step() {
    //printf("Entered step\n");
        if (pc / 4 >= 50) {
            printf("Nothing to step\n");
            S->current_index = -1;
            return;
        }

        Instruction instr = instructions[pc / 4];
        if (instr.instrc == NULL) {
            printf("Nothing to step\n");
            S->current_index = -1;
            return;
        }
        int rd = string_to_register(instructions[pc / 4].rd);
        int rs1 = string_to_register(instructions[pc / 4].rs1);
        int rs2 = string_to_register(instructions[pc / 4].rs2);
        int imm = string_to_immediate(instructions[pc / 4].imm);

        next_pc = pc + 4;


        if (strcmp(instr.instrc, "add") == 0) {
            registers[rd] = registers[rs1] + registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "sub") == 0) {
            registers[rd] = registers[rs1] - registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "and") == 0) {
            registers[rd] = registers[rs1] & registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "or") == 0) {
            registers[rd] = registers[rs1] | registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "xor") == 0) {
            registers[rd] = registers[rs1] ^ registers[rs2];
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "sll") == 0) {
            registers[rd] = registers[rs1] << (registers[rs2] & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "srl") == 0) {
            registers[rd] = ((uint64_t)registers[rs1]) >> (registers[rs2] & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        } else if (strcmp(instr.instrc, "sra") == 0) {
            registers[rd] = ((int64_t)registers[rs1]) >> (registers[rs2] & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].rs2, pc);
        }
        else if (strcmp(instr.instrc, "addi") == 0) {
            registers[rd] = registers[rs1] + imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "andi") == 0) {
            registers[rd] = registers[rs1] & imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "ori") == 0) {
            registers[rd] = registers[rs1] | imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "xori") == 0) {
            registers[rd] = registers[rs1] ^ imm;
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "slli") == 0) {
            registers[rd] = registers[rs1] << (imm & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "srli") == 0) {
            registers[rd] = ((uint64_t)registers[rs1]) >> (imm & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        } else if (strcmp(instr.instrc, "srai") == 0) {
            registers[rd] = ((int64_t)registers[rs1]) >> (imm & 0x1F);
            printf("Executed: %s %s, %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].rs1, instructions[pc/4].imm, pc);
        }
        else if (strcmp(instr.instrc, "ld") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 8, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lw") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 4, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lh") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 2, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lb") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 1, 0);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lwu") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 4, 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lhu") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 2, 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        } else if (strcmp(instr.instrc, "lbu") == 0) {
            registers[rd] = load_memory(registers[rs1] + imm, 1, 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "R");
            }
        }
        else if (strcmp(instr.instrc, "sd") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 8);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        } else if (strcmp(instr.instrc, "sw") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 4);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        } else if (strcmp(instr.instrc, "sh") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 2);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        } else if (strcmp(instr.instrc, "sb") == 0) {
            store_memory(registers[rs1] + imm, registers[rs2], 1);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs2, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
            if(cache_enabled) {
                access_cache(CACHE,registers[rs1] + imm, "W");
            }
        }
        else if (strcmp(instr.instrc, "beq") == 0) {
            if (registers[rs1] == registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bne") == 0) {
            if (registers[rs1] != registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "blt") == 0) {
            if ((int64_t)registers[rs1] < (int64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bge") == 0) {
            if ((int64_t)registers[rs1] >= (int64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bltu") == 0) {
            if ((uint64_t)registers[rs1] < (uint64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        } else if (strcmp(instr.instrc, "bgeu") == 0) {
            if ((uint64_t)registers[rs1] >= (uint64_t)registers[rs2]) {
                for (int i = 0; i < 50; i++) {
                    if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                        label_line = labels[i].lineNum;
                    }
                }
                imm = (label_line-labels[pc/4].lineNum)*4;
                next_pc = pc + imm;
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
            else {
                printf("Executed %s %s, %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rs1, instructions[pc/4].rs2, instructions[pc/4].imm, pc);
            }
        }
        else if (strcmp(instr.instrc, "jal") == 0) {
            registers[rd] = pc + 4;
            for (int i = 0; i < 50; i++) {
                if (labels[i].Label != NULL && strcmp(instr.imm, labels[i].Label) == 0) {
                    label_line = labels[i].lineNum;
                }
            }
            imm = (label_line-labels[pc/4].lineNum)*4;
            next_pc = pc + imm;
            push(S,labels[label_line].Label,pc/4+1);
            //printf("Next PC 0x%08lx\n",next_pc);
            printf("Executed %s %s, %s PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, pc);

        } else if (strcmp(instr.instrc, "jalr") == 0) {
            registers[rd] = pc + 4;
            //printf("register rs1: 0x%08lx\n",registers[rs1]);
            next_pc = (registers[rs1] + imm);
            pop(S);
            //printf("Next PC 0x%08lx\n",next_pc);
            printf("Executed: %s %s, %s(%s) PC: 0x%08lx\n",instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, instructions[pc/4].rs1, pc);
        }
        else if (strcmp(instr.instrc, "lui") == 0) {
            registers[rd] = imm << 12;
            printf("Executed: %s %s, %s PC: 0x%08lx\n", instructions[pc/4].instrc, instructions[pc/4].rd, instructions[pc/4].imm, pc);
        }
        //else {printf("hi\n");}
        if (strcmp(instr.instrc, "jalr") != 0) push(S,NULL,pc/4 +1);
        pc = next_pc;
        executingLineNum++;
        registers[0] = 0;
        
        // printf("PC has been updated 0x%08lx\n",pc);
        // printf("%d execution\n",executingLineNum);
}

void display_registers() {
    printf("Registers:\n");
    for (int i = 0; i < 32; i++) {
        printf("x%d: 0x%016lx\n", i, registers[i]);
    }
}

void set_breakpoint(int line) {
    if(breakpoints[0] == -1) {
        breakpoints[0] = line;
        printf("Breakpoint set at line %d\n", line);
        return;
    }
    else if(breakpoints[1] == -1) {
        breakpoints[1] = line;
        printf("Breakpoint set at line %d\n", line);
        return;
    }
    else if(breakpoints[2] == -1) {
        breakpoints[2] = line;
        printf("Breakpoint set at line %d\n", line);
        return;
    }
    else if(breakpoints[3] == -1) {
        breakpoints[3] = line;
        printf("Breakpoint set at line %d\n", line);
        return;
    }
    else if(breakpoints[4] == -1) {
        breakpoints[4] = line;
        printf("Breakpoint set at line %d\n", line);
        return;
    }
    else {
        printf("No breakpoints can be set\n");
        return;
    }
}

void delete_breakpoint(int line) {
    if (breakpoints[0] == line) {
        breakpoints[0] = -1;
        printf("Breakpoint is deleted at line %d\n", line);
        return;
    }
    else if (breakpoints[1] == line) {
        breakpoints[1] = -1;
        printf("Breakpoint is deleted at line %d\n", line);
        return;
    }
    else if (breakpoints[2] == line) {
        breakpoints[2] = -1;
        printf("Breakpoint is deleted at line %d\n", line);
        return;
    }
    else if (breakpoints[3] == line) {
        breakpoints[3] = -1;
        printf("Breakpoint is deleted at line %d\n", line);
        return;
    }
    else if (breakpoints[4] == line) {
        breakpoints[4] = -1;
        printf("Breakpoint is deleted at line %d\n", line);
        return;
    }
    else {
        printf("No breakpoint at line %d is found\n", line);
        return;
    }
}

void print_memory(uint64_t addr,int count) {
    for (int i=0; i < count; i++){
        uint64_t temp = addr + i; 
        printf("Memory[0x%05lx] = 0x%02x\n",temp , (uint8_t)memory[addr+i]);
    }
}

int main() {
    S = createEmptyStack(S);
    cache_enabled = false;
    char command[100];
    printf("RISC-V SIMULATOR\n");
    while (1) {
        printf("> ");
        fgets(command, sizeof(command), stdin);

        if (strncmp(command, "load", 4) == 0) {
            pc = 0x0000000000000000;
            for (int i=0; i<32; i++) {
                registers[i] = 0;
            }
            sscanf(command, "load %s", filename);
            load_file(filename);
            FILE *file = fopen(filename, "r");
            parsefile(file);
        } 
        else if (strncmp(command, "run", 3) == 0) {
            run_program(instructions);
        } 
        else if (strncmp(command, "regs", 4) == 0) {
            display_registers();
        } 
        else if (strncmp(command, "mem", 3) == 0) {
            uint64_t addr;
            int count;
            sscanf(command, "mem %lx %d", &addr, &count);
            print_memory(addr, count);
        } 
        else if (strncmp(command, "step", 4) == 0) {
            step();
        } 
        else if (strncmp(command, "break", 5) == 0) {
            int line;
            sscanf(command, "break %d", &line);
            set_breakpoint(line);
        } 
        else if (strncmp(command, "del break", 9) == 0) {
            int line;
            sscanf(command, "del break %d", &line);
            delete_breakpoint(line);
        } 
        else if (strncmp(command, "show-stack", 10) == 0) {
                show_stack(S);
        } 
        else if (strncmp(command, "exit", 4) == 0) {
            exit_program();
        } 
        else if (strncmp(command, "cache_sim enable", 16) == 0) {
            char config[256];
            sscanf(command,"cache_sim enable %s",config);
            FILE *config_file = fopen(config, "r");
            read_config(config_file);
            cache_enabled = true;
            CACHE = initialize_cache();
        }
        else if (strncmp(command, "cache_sim disable", 17) == 0) {
            cache_enabled = false;
        }
        else if (strncmp(command, "cache_sim status", 16) == 0) {
            if(cache_enabled) {
                printf("Cache enabled\n");
                printf("Cache Size: %lld\nBlock Size: %ld\nAssociativity: %ld\nReplacement Policy: %sWrite Back Policy: %s\n",cache_size,block_size,associativity,replacement_policy,write_policy); 
            } else {
                printf("Cache disabled\n");
            }
        }
        else if (strncmp(command, "cache_sim invalidate", 20) == 0) {
            cache_sim_invalidate(CACHE);
        }
        else if (strncmp(command, "cache_sim dump", 14) == 0) {
            char myFile[256];
            sscanf(command,"cache_sim dump %s",myFile);
            cache_sim_dump(CACHE,myFile);
        }
        else if (strncmp(command, "cache_sim stats", 15) == 0) {
            cache_sim_stats(CACHE);
        }
        else {
            printf("Unknown command\n\n");
        }
    }
    return 0;
}
