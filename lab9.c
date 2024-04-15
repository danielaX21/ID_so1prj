#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

void open_directory(const char* directory_name, DIR **dir_ptr) {
    *dir_ptr = opendir(directory_name);
    if (*dir_ptr == NULL) {
        printf("Eroare la deschiderea directorului\n");
        exit(1);
    }
}

void close_directory(DIR **dir_ptr) {
    if (closedir(*dir_ptr)) {
        printf("Eroare la inchiderea directorului.\n");
        exit(2);
    }
}

void write_snapshot(int file, const char* data) {
    if (write(file, data, strlen(data)) < 0) {
        printf("Eroare la scrierea in fisier.\n");
        exit(3);
    }
}

// void create_snapshot(const char* directory_name,int file) {
    void create_snapshot(const char* directory_name) {

    char snapshot_path[1024];
    char name[100];
    //snprintf(name,sizeof(name),"%s", directory_name);

    snprintf(snapshot_path,sizeof(snapshot_path),"%s/snapshot_.txt",directory_name);
    int newfile = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR); // deschide fișierul sau creează-l dacă nu există
    if (newfile < 0) {
        printf("Eroare la deschiderea fisierului.\n");
        exit(1);
    }

    DIR *dir;
    struct dirent *entry;
    struct stat file_info;

    open_directory(directory_name, &dir);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char file_path[1000];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory_name, entry->d_name);
            if (stat(file_path, &file_info) < 0) {
                printf("Eroare la citirea informatiei despre fisier: %s\n", file_path);
            } 
            else {
                char file_type[1000];
                if (S_ISREG(file_info.st_mode)) {
                    strcpy(file_type, "Regular file");
                } else if (S_ISDIR(file_info.st_mode)) {
                    strcpy(file_type, "Directory");
                } else if (S_ISCHR(file_info.st_mode)) {
                    strcpy(file_type, "Character device");
                } else if (S_ISBLK(file_info.st_mode)) {
                    strcpy(file_type, "Block device");
                } else if (S_ISFIFO(file_info.st_mode)) {
                    strcpy(file_type, "FIFO (pipe)");
                } else {
                    strcpy(file_type, "Unknown");
                }

                char buffer[1024]; // Alocare de memorie pt a construi șirul de date
                int n = snprintf(buffer, sizeof(buffer), "\nFile Name:                  %s\n"
                                                            "File Type:                  %s\n"
                                                            "Inode Number:               %ju\n"
                                                            "Last Status Change:         %s"
                                                            "Last File Access:           %s"
                                                            "Last File Modification:     %s\n",
                                    entry->d_name,
                                    file_type,
                                    file_info.st_ino,
                                    ctime(&file_info.st_ctime),
                                    ctime(&file_info.st_atime),
                                    ctime(&file_info.st_mtime));
                if (n < 0) {
                    printf("Eroare la construirea datelor pentru fisierul: %s\n", file_path);
                } else {
                    write_snapshot(newfile, buffer); // Scrierea datelor în fișier
                }
            }
        }
    }
    close_directory(&dir);
    close(newfile);
}

// void traverse_directory(const char* directory_name, int level,int file) {
    void traverse_directory(const char* directory_name, int level) {

    DIR *dir;
    struct dirent *entry;
    struct stat file_info;

    open_directory(directory_name, &dir);

    for (int i = 0; i < level; i++) {
        printf("  "); //spații de indentare
    }
    printf("|_ %s\n", directory_name);

    create_snapshot(directory_name);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char file_path[1000];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory_name, entry->d_name);
            if (stat(file_path, &file_info) < 0) {
                printf("Eroare la citirea informatiei despre: %s\n", file_path);
            } else {
                if (S_ISDIR(file_info.st_mode)) {
                    traverse_directory(file_path, level + 1);
                } else {
                    for (int i = 0; i < level + 1; i++) {
                        printf("  "); 
                    }
                    printf("|_ %s (File)\n", entry->d_name);
                }
            }
        }
    }

    close_directory(&dir);
}

int main(int argc, char** argv) {
    if (argc < 2 || argc >= 11) {
        perror("Numar incorect de argumente!\n");
        exit(3);
    }
//old version
    // int file = open("snapshots.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR); // deschide fișierul sau creează-l dacă nu există
    // if (file < 0) {
    //     printf("Eroare la deschiderea fisierului.\n");
    //     return 1;
    // }

    for (int i = 1; i < argc; i++) {
        char* directory_name = argv[i];
        //traverse_directory(directory_name, 0,file);
        //create_snapshot(directory_name,file);
        //write_snapshot(0, "/////////////////////////////////////////////////end call\n");
        traverse_directory(directory_name, 0);
        create_snapshot(directory_name);
    }

    //close(file);
    return 0;
}