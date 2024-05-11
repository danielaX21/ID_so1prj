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
#define MAX_BUFFER_SIZE 256
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

char* check_for_malicious(const char* file_path, const char* file_name) {
    char* result = NULL;
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) == -1) {
        perror("Error creating pipe");
        exit(EXIT_FAILURE);
    }

    pid = fork();

    if (pid == -1) {
        perror("Error forking process");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { 
        close(pipefd[0]); 
        dup2(pipefd[1], STDOUT_FILENO); 
        close(pipefd[1]); 

        execl("./verify_malicious.sh", "./verify_malicious.sh", file_path, file_name, NULL);

        perror("Error executing script");
        exit(EXIT_FAILURE);
    } else { 
        close(pipefd[1]); 
        result = (char*)malloc(MAX_BUFFER_SIZE * sizeof(char));
        if (result == NULL) {
            perror("Error allocating memory");
            exit(EXIT_FAILURE);
        }
        read(pipefd[0], result, MAX_BUFFER_SIZE); 
        close(pipefd[0]); 

        // Verificăm dacă fișierul nu are niciun drept
        struct stat file_stat;
        if (stat(file_path, &file_stat) == 0) {
            if ((file_stat.st_mode & S_IRWXU) == 0 && (file_stat.st_mode & S_IRWXG) == 0 && (file_stat.st_mode & S_IRWXO) == 0) {
                strcpy(result, "MALICIOUS"); // Considerăm fișierul fără niciun drept ca fiind suspect
            }
        } else {
            perror("Error getting file permissions");
            exit(EXIT_FAILURE);
        }

        wait(NULL); 
    }
    return result;
}


void isolate_malicious(const char* source_dir, const char* suspect_file, const char* isolated_dir) {
    char source_path[strlen(source_dir) + strlen(suspect_file) + 2];
    strcpy(source_path, source_dir);
    strcat(source_path, "/");
    strcat(source_path, suspect_file);

    char destination_path[strlen(isolated_dir) + strlen(suspect_file) + 1];
    strcpy(destination_path, isolated_dir);
    strcat(destination_path, "/");
    strcat(destination_path, suspect_file);

    if (rename(source_path, destination_path) == 0) {
        printf("File moved successfully.\n");
    } else {
        perror("Error moving file");
        exit(EXIT_FAILURE);
    }
}


void create_snapshot(const char* directory_name, const char* output_directory, const char* isolated_directory) {
    char snapshot_path[1024];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/snapshot_%s.txt", output_directory, directory_name);
    int newfile = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (newfile <0) {
        printf("Eroare la deschiderea fisierului de snapshot-uri.\n");
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
            if (lstat(file_path, &file_info) < 0) {
                printf("Eroare la citirea informatiei despre fisier: %s\n", file_path);
            }
            else {
                // Verific dacă fișierul este considerat malitios
                char* result = check_for_malicious(file_path, entry->d_name);
                if (strcmp(result, "MALICIOUS") == 0) {
                    printf("Fișierul %s este considerat malitios. Se va muta în directorul izolat.\n", entry->d_name);
                    isolate_malicious(directory_name, entry->d_name, isolated_directory);
                    free(result);
                    continue; // Trec la următorul fișier, nu cream snapshot pentru acesta
                }
                free(result);

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

                char permissions[10];
                snprintf(permissions, sizeof(permissions), "%c%c%c%c%c%c%c%c%c",
                         (file_info.st_mode & S_IRUSR) ? 'r' : '-',
                         (file_info.st_mode & S_IWUSR) ? 'w' : '-',
                         (file_info.st_mode & S_IXUSR) ? 'x' : '-',
                         (file_info.st_mode & S_IRGRP) ? 'r' : '-',
                         (file_info.st_mode & S_IWGRP) ? 'w' : '-',
                         (file_info.st_mode & S_IXGRP) ? 'x' : '-',
                         (file_info.st_mode & S_IROTH) ? 'r' : '-',
                         (file_info.st_mode & S_IWOTH) ? 'w' : '-',
                         (file_info.st_mode & S_IXOTH) ? 'x' : '-');
                char buffer[1024];
                int n = snprintf(buffer, sizeof(buffer), "\nFile Name:                  %s\n"
                                                            "File Type:                  %s\n"
                                                            "Permissions:                %s\n"
                                                            "Inode Number:               %ju\n"
                                                            "Last Status Change:         %s"
                                                            "Last File Access:           %s"
                                                            "Last File Modification:     %s\n",
                                    entry->d_name,
                                    file_type,
                                    permissions,
                                    file_info.st_ino,
                                    ctime(&file_info.st_ctime),
                                    ctime(&file_info.st_atime),
                                    ctime(&file_info.st_mtime));
                if (n < 0) {
                    printf("Eroare la construirea datelor pentru fisierul: %s\n", file_path);
                } else {
                    write_snapshot(newfile, buffer);
                }
            }
        }
    }

    close_directory(&dir);
    close(newfile);
}


/*void traverse_directory(const char* directory_name, const char* output_directory, int level) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_info;

    open_directory(directory_name, &dir);

    for (int i = 0; i < level; i++) {
        printf("  "); //spații de indentare
    }
    printf("|_ %s\n", directory_name);

    // Verificăm drepturile de acces ale directorului
    check_file_permissions(directory_name);

    // Parcurgem directorul și verificăm drepturile de acces pentru fiecare fișier și director
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
*/
void create_output_directory(const char* output_directory) {
    struct stat st;
    if (stat(output_directory, &st) == -1) {
        // Directorul nu există, îl creăm
        if (mkdir(output_directory, 0777) == -1) {
            perror("Eroare la crearea directorului de iesire\n");
            exit(EXIT_FAILURE);
        } else {
            printf("Directorul de iesire \"%s\" a fost creat cu succes.\n", output_directory);
        }
    }
}

//void create_child_processes(char* output_directory, char* unique_directories[], int unique_count) {
  void create_child_processes(char* output_directory, char* isolated_directory, char* unique_directories[], int unique_count){
    // Parcurgem directoarele unice și creăm snapshot-urile în procese copil
    for (int i = 0; i < unique_count; i++) {
        pid_t pid = fork(); // Creăm un proces copil

        if (pid == -1) {
            // Eroare la fork
            perror("Eroare la fork!\n");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // Suntem în procesul copil
            //traverse_directory(unique_directories[i], output_directory, 0); // Call traverse_directory here
            create_snapshot(unique_directories[i], output_directory, isolated_directory);
            //create_snapshot(unique_directories[i], output_directory);
            //create_snapshot(const char* directory_name, const char* output_directory, const char* isolated_directory)
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
}

void check_file_permissions(const char* file_path) {
    struct stat file_stat;
    if (stat(file_path, &file_stat) == 0) {
        printf("Drepturi de acces pentru '%s':\n", file_path);
        printf("Owner: %s%s%s\n", (file_stat.st_mode & S_IRUSR) ? "r" : "-", (file_stat.st_mode & S_IWUSR) ? "w" : "-", (file_stat.st_mode & S_IXUSR) ? "x" : "-");
        printf("Group: %s%s%s\n", (file_stat.st_mode & S_IRGRP) ? "r" : "-", (file_stat.st_mode & S_IWGRP) ? "w" : "-", (file_stat.st_mode & S_IXGRP) ? "x" : "-");
        printf("Others: %s%s%s\n", (file_stat.st_mode & S_IROTH) ? "r" : "-", (file_stat.st_mode & S_IWOTH) ? "w" : "-", (file_stat.st_mode & S_IXOTH) ? "x" : "-");
    } else {
        printf("Eroare la verificarea drepturilor de acces pentru '%s'\n", file_path);
    }
}

 int main(int argc, char** argv) {

    if (argc < 4 || argc >= MAXD + 5) {
        perror("Numar incorect de argumente!\n");
        exit(3);
    }

    char* output_directory = NULL;
    char* isolated_directory = NULL;
    char* unique_directories[MAXD];
    int unique_count = 0;

    // Parcurgem argumentele și identificăm opțiunile -o și -s pentru directoarele de ieșire și izolate
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_directory = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            isolated_directory = argv[i + 1];
            i++;
        } else {
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
    

    // Verificăm dacă au fost specificate directoarele de ieșire și izolate
    if (output_directory == NULL || isolated_directory == NULL) {
        perror("Nu au fost specificate directorul de iesire (-o) sau directorul izolat (-s)!\n");
        exit(3);
    }

    // Creăm directoarele de ieșire și izolate dacă nu există deja
    create_output_directory(output_directory);
    create_output_directory(isolated_directory);

    // Apelăm funcția care creează procesele copil
    //create_child_processes(output_directory, unique_directories, unique_count);
    create_child_processes(output_directory, isolated_directory, unique_directories, unique_count);

    return 0;
}