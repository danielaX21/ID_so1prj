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

#define MAXD 10

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

void create_snapshot(const char* directory_name, const char* output_directory) {

    char snapshot_path[1024];
	// Construim calea către fișierul de snapshot folosind directorul de ieșire și numele directorului
	 snprintf(snapshot_path, sizeof(snapshot_path), "%s/snapshot_%s.txt", output_directory, directory_name);
	 // Deschidem fișierul de snapshot
 int newfile = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH); // deschide fișierul sau creează-l dacă nu există
    if (newfile <0) {
        printf("Eroare la deschiderea fisierului de snapshot-uri.\n");
        exit(1);
    }

    DIR *dir;
    struct dirent *entry;
    struct stat file_info;

    open_directory(directory_name, &dir);

      
   

    // Parcurgem directorul și scriem informațiile despre fișiere în fișierul de snapshot
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char file_path[1000];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory_name, entry->d_name);
            if (lstat(file_path, &file_info) < 0) {
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
                    
                    write_snapshot(newfile, buffer);// Scrierea datelor în fișier
                }
            }
        }
    }

    // Închidem fișierul de snapshot
    close_directory(&dir);
	close(newfile);
}

// void traverse_directory(const char* directory_name, int level,int file) {
   void traverse_directory(const char* directory_name, const char* output_directory, int level) {

    DIR *dir;
    struct dirent *entry;
    struct stat file_info;

    open_directory(directory_name, &dir);

    for (int i = 0; i < level; i++) {
        printf("  "); //spații de indentare
    }
    printf("|_ %s\n", directory_name);

    create_snapshot(directory_name, output_directory);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char file_path[1000];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory_name, entry->d_name);
            if (stat(file_path, &file_info) < 0) {
                printf("Eroare la citirea informatiei despre: %s\n", file_path);
            } else {
                if (S_ISDIR(file_info.st_mode)) {
                    traverse_directory(file_path, output_directory, level + 1);
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




void create_output_directory(const char* output_directory) {
    struct stat st;
    if (stat(output_directory, &st) == -1) {
        // Directorul nu există, îl creăm
        if (mkdir(output_directory, 0700) == -1) {
            perror("Eroare la crearea directorului de iesire\n");
            exit(EXIT_FAILURE);
        } else {
            printf("Directorul de iesire \"%s\" a fost creat cu succes.\n", output_directory);
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 3 || argc >= MAXD + 4) {
        perror("Numar incorect de argumente!\n");
        exit(3);
    }

    char* output_directory = NULL;
    char* unique_directories[MAXD]; // Vector pentru stocarea directoriilor unice
    int unique_count = 0; // Contor pentru numărul de directoare unice

    // Parcurgem argumentele și identificăm opțiunea -o pentru directorul de ieșire
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_directory = argv[i + 1];
            i++; // Trecem peste opțiunea -o și directorul asociat
        } else {
            // Dacă argumentul nu este opțiunea -o, verificăm dacă este un director unic
            int is_unique = 1;
            for (int j = 0; j < unique_count; j++) {
                if (strcmp(argv[i], unique_directories[j]) == 0) {
                    is_unique = 0; // Directorul nu este unic
                    break;
                }
            }

            if (is_unique) {
                unique_directories[unique_count] = argv[i];
                unique_count++;
            }
        }
    }

    // Verificăm dacă a fost specificat directorul de ieșire
    if (output_directory == NULL) {
        perror("Nu a fost specificat directorul de iesire (-o)!\n");
        exit(3);
    }

    // Creăm directorul de ieșire dacă nu există deja
    create_output_directory(output_directory);

    // Parcurgem directoarele unice și creăm snapshot-urile în procese copil
    for (int i = 0; i < unique_count; i++) {
        pid_t pid = fork(); // Creăm un proces copil

        if (pid == -1) {
            // Eroare la fork
            perror("Eroare la fork!\n");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // Suntem în procesul copil
            create_snapshot(unique_directories[i], output_directory);
            printf("Snapshot pentru '%s' creat cu succes.\n", unique_directories[i]);
            exit(EXIT_SUCCESS);
        }
    }

    // Așteptăm terminarea tuturor proceselor copil
    int status;
    pid_t wpid;
    while ((wpid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            printf("Procesul copil %d a fost terminat cu codul de ieșire %d.\n", wpid, WEXITSTATUS(status));
        } else {
            printf("Procesul copil %d a fost terminat în mod anormal.\n", wpid);
        }
    }

    return 0;
}
