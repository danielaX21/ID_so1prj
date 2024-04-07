#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
//#include <libgen.h>
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
void create_snapshot(const char* directory_name, FILE *snapshot_file) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_info;
    open_directory(directory_name, &dir);

while ((entry = readdir(dir)) != NULL) {
         if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){
        char file_path[200];
        snprintf(file_path, sizeof(file_path), "%s/%s", directory_name, entry->d_name);
        if (stat(file_path, &file_info) < 0) {
            printf("Eroare la citirea informatiei despre fisier: %s\n", file_path);
        } 
        else {
            char file_type[200];
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
            }/* else if (S_ISSOCK(file_info.st_mode)) {
                strcpy(file_type, "Socket");
            } else if (S_ISLNK(file_info.st_mode)) {
                strcpy(file_type, "Symbolic link");
            } */else {
                strcpy(file_type, "Unknown");
            }
            
            fprintf(snapshot_file, "\nFile Name:                  %s\n"
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
        }
    }
    }
    close_directory(&dir);
}


void traverse_directory(const char* directory_name, int level, FILE *snapshot_file) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_info;

    open_directory(directory_name, &dir);

    for (int i = 0; i < level; i++) {
        printf("  "); //spatii indentare
    }
    printf("|_ %s\n", directory_name);
    create_snapshot(directory_name, snapshot_file);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) //ignora fisierele specificate
        {
            char file_path[200];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory_name, entry->d_name);
            if (stat(file_path, &file_info) < 0) {
                printf("Eroare la citirea informatiei despre : %s\n", file_path);
            } else {
                if (S_ISDIR(file_info.st_mode)) {
                    traverse_directory(file_path, level + 1, snapshot_file); //cresc level-ul cand trecla subdirectoare
                } else {
                    for (int i = 0; i < level + 1; i++) {
                        printf("  "); 
                    }
                    printf("|_ %s (File)\n", entry->d_name); // daca nu e director  printez file(pt fisiere.txt in special)
                }
            }
        }
    }

    close_directory(&dir);
}

int main(int argc, char** argv) {
    if(argc<2 || argc>=11)
    {
      perror("Numar incorect de argumente!\n");
      exit(3);
    }
    FILE *snapshot_file = fopen("snapshots.txt", "w+");// suprascrie fisierul
    //FILE *snapshot_file = fopen("snapshots.txt", "a"); // adauga la final dupa fiecare apel datele
    if (snapshot_file == NULL) {
        printf("Eroare la deschiderea fisierului.\n");
        return 1;
    }
for(int i=1;i<argc;i++){// se parcurgere directorul initial si se salvezaza datele in fiserul pt snapshots
    char* directory_name = argv[i];
    traverse_directory(directory_name, 0, snapshot_file);
  
fprintf(snapshot_file, "/////////////////////////////////////////////////end call");
    // delimitare dupa fiecare apel al functiei
}
 fclose(snapshot_file);
 return 0;
}