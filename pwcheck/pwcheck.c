#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define MAX_PWD_LEN 100
#define IS_DOWNCASE(c) (c >= 'a' && c <= 'z')
#define IS_UPCASE(c) (c >= 'A' && c <= 'Z')
#define IS_DIGIT(c) (c >= '0' && c <= '9')
#define IS_SPECIAL(c) (((int)c >= 32 && (int)c <= 47) || ((int)c >= 58 && (int)c <= 64) || ((int)c >= 91 && (int)c <= 96) || ((int)c >= 123 && (int)c <= 126))

typedef enum in_errors {
  E_EOF = -1,
  E_OK = 0,
  E_ARGS,
  E_MAX_PWD,
  E_RULE_1,
  E_RULE_2,
  E_RULE_3,
  E_RULE_4,
  E_UNKNOWN
} in_error_t;

void print_usage(in_error_t err) {
  char const *msg = "Usage: pwcheck [-l LEVEL] [-p PARAM] [--stats]\n" \
  "  -l   LEVEL   Celé číslo v intervalu [1, 4], které určuje požadovanou úroveň bezpečnosti.\n" \
  "  -p   PARAM   Kladné celé číslo, které určuje dodatečný parametr pravidel.\n" \
  "  --stats      Pokud je zadané, určuje, zda se na konci programu mají vypsat souhrnné statistiky analyzovaných hesel.\n";
  if (err == E_OK) {
    fprintf(stdout, msg);
  } else {
    fprintf(stderr, msg);
  }
}

int str_len(char *str) {
  int len = 0;

  while (*str++ != '\0') len++;

  return len;
}

int has_char(char *str, char c) {
  for (int i = 0; str[i] != '\0'; i++) {
    if (str[i] == c) return 1;
  }
  return 0;
}

int has_str(char *orig, char *sub, int *idx) {
  int orig_len = str_len(orig);
  int sub_len = str_len(sub);
  int has = 0;
  for (int i = 0; i < orig_len - sub_len; i++) {
    for (int j = 0; j < sub_len; j++) {
      has = 1;
      if (orig[i + j] != sub[j]) {
        has = 0;
        break;
      }
    }
    if (has) {
      *idx = i;
      break;
    }
  }

  return has;
}

void add_char(char *dest, char c) {
  int len = str_len(dest);
  dest[len] = c;
  dest[len + 1] = '\0';
}

in_error_t get_level(char *option, int *level) {
  char *garbage = NULL;
  int lvl = strtol(option, &garbage, 10);
  if (1 > lvl || lvl > 4) {
    fprintf(stderr, "LEVEL must be within [1, 4] interval.\n");
    return E_ARGS;
  }
  *level = lvl;
  return E_OK;
}

in_error_t get_param(char *option, int *param) {
  char *garbage = NULL;
  int par = strtol(option, &garbage, 10);
  if (par <= 0) {
    fprintf(stderr, "PARAM must be positive integer.\n");
    return E_ARGS;
  }
  *param = par;
  return E_OK;
}

in_error_t parse_options(int argc, char* const* argv, int *level, int *param, int *show_stats) {
  if (argc < 2) {
    fprintf(stderr, "No arguments were specified.\n");
    return E_ARGS;
  }
  int opt = 0;
  int opt_idx = 0;
  in_error_t err = E_OK;
  struct option long_options[] = {
    {"stats", no_argument, show_stats, 1},
  };
  while (((opt = getopt_long(argc, argv, "-l:p:", long_options, &opt_idx)) != -1)) {
    if (err != E_OK) return err;
    switch (opt) {
      case 0:
        // Ignore since the flag show_stats will be set to 1 by
        // getopt_long automatically
      break;
      case 'l':
        err = get_level(optarg, level);
      break;
      case 'p':
        err = get_param(optarg, param);
      break;
      case 1:
      {
        if (*level && *param) break;
        if (!*level) {
          err = get_level(optarg, level);
        } else if (!*param) {
          err = get_param(optarg, param);
        }
      }
      break;
      case '?':
      default:
        err = E_ARGS;
      break;
    }
  }
  if (err != E_OK) return err;
  // If everything is OK, but level or param is 0, set to default 1
  if (!*level) *level = 1;
  if (!*param) *param = 1;
  return err;
}

in_error_t apply_rule_1(char *password) {
  int has_cap = 0;
  int has_smal = 0;
  for (int i = 0; password[i] != '\0'; i++) {
    if (IS_UPCASE(password[i])) has_cap = 1;
    if (IS_DOWNCASE(password[i])) has_smal = 1;
  }
  if (has_cap && has_smal) return E_OK;

  return E_RULE_1;
}

in_error_t apply_rule_2(char *password, int param) {
  in_error_t err = E_OK;
  int groups = 0x0;
  for (int i = 0; password[i] != '\0'; i++) {
    if (IS_DOWNCASE(password[i])) groups |= 0x1;
    if (IS_UPCASE(password[i])) groups |= 0x10;
    if (IS_DIGIT(password[i])) groups |= 0x100;
    if (IS_SPECIAL(password[i])) groups |= 0x1000;
  }
  switch (param) {
    case 1:
      err = groups >= 0x1 ? E_OK : E_RULE_2;
    break;
    case 2:
      err = groups >= 0x11 ? E_OK : E_RULE_2;
    break;
    case 3:
      err = groups >= 0x111 ? E_OK : E_RULE_2;
    break;
    case 4:
    default:
      err = groups >= 0x1111 ? E_OK : E_RULE_2;
    break;
  }

  return err;
}

in_error_t apply_rule_3(char *password, int param) {
  int occurs = 1;
  int pwd_len = str_len(password);
  for (int i = 0; i < pwd_len - param; i++) {
    for (int j = 1; j <= param; j++) {
      if (password[i] != password[i + j]) break;

      occurs++;
      if (occurs == param) return E_RULE_3;
    }
    occurs = 1;
  }

  return E_OK;
}

in_error_t apply_rule_4(char *password, int param) {
  int pwd_len = str_len(password);
  int occurs = 1;
  for (int i = 0; i < pwd_len - param; i++) {
    char substr[MAX_PWD_LEN + 1] = { '\0', };
    // Create substring to look for based on param length
    for (int j = 0; j < param; j++) {
      substr[j] = password[i + j];
    }
    int sub_idx = 0;
    int curr_idx = i + param;
    while (has_str(password + curr_idx, substr, &sub_idx)) {
      // sub_idx is the index the substring starts from
      // We need to continue looking from the next char instead
      curr_idx += (sub_idx + 1);
      occurs += 1;
    }
    if (occurs >= 2) return E_RULE_4;
  }

  return E_OK;
}

in_error_t check_password(char *password, int level, int param) {
  in_error_t err = E_OK;

  err = apply_rule_1(password);
  if (err != E_OK || level == 1) return err;

  err = apply_rule_2(password, param);
  if (err != E_OK || level == 2) return err;

  err = apply_rule_3(password, param);
  if (err != E_OK || level == 3) return err;

  err = apply_rule_4(password, param);
  if (err != E_OK || level == 4) return err;

  return err;
}

void print_stats(int char_cnt, int min_len, double avg_len) {
  printf("Statistika:\n");
  printf("Ruznych znaku: %d\n", char_cnt);
  printf("Minimalni delka: %d\n", min_len);
  printf("Prumerna delka: %.1f\n", avg_len);
}

void save_uniq(char *dest, char *src) {
  for (int i = 0; src[i] != '\0'; i++) {
    if (!has_char(dest, src[i])) {
      add_char(dest, src[i]);
    }
  }
}

in_error_t read_password(char *dest, char *uniq) {
  if (fgets(dest, MAX_PWD_LEN + 2, stdin) == NULL) return E_EOF;

  int pwd_len = str_len(dest);
  // Remove \n character since fgets can read and save that as part of a password
  if (dest[pwd_len - 1] == '\n') {
    dest[pwd_len - 1] = '\0';
    pwd_len -= 1;
  }

  if (pwd_len > MAX_PWD_LEN) {
    fprintf(stderr, "Password must be no longer then 100 characters.\n");
    return E_MAX_PWD;
  }
  // If everything is OK save uniq characters
  save_uniq(uniq, dest);
  return E_OK;
}

int main(int argc, char *argv[]) {
  in_error_t err = E_OK;
  int show_stats = 0;
  int level = 0;
  int param = 0;
  if ((err = parse_options(argc, argv, &level, &param, &show_stats)) != E_OK) {
    print_usage(err);
    return err;
  }

  int pwd_count = 0;
  int min_len = MAX_PWD_LEN;
  double avg_len = 0.0;
  char curr_pwd[MAX_PWD_LEN + 1] = { '\0', };
  char uniq_chars[MAX_PWD_LEN + 1] = { '\0', };
  while ((err = read_password(curr_pwd, uniq_chars)) != E_EOF) {
    if (err != E_OK) break;

    pwd_count += 1;
    int curr_len = str_len(curr_pwd);
    // Set minimal length of a password
    min_len = curr_len < min_len ? curr_len : min_len;
    avg_len += curr_len;
    // Apply rules to the password
    in_error_t pwd_err = check_password(curr_pwd, level, param);
    // If OK print the password
    if (!pwd_err) {
      printf("%s\n", curr_pwd);
    }
    // "Clear" old password
    curr_pwd[0] = '\0';
  }
  if (err == E_EOF) {
    // Special case when no passwords were given
    if (pwd_count == 0) {
      pwd_count = 1;
      min_len = 0;
    }
    err = E_OK;
  }
  if (err != E_OK) return err;

  avg_len = avg_len / pwd_count;
  if (show_stats) print_stats(str_len(uniq_chars), min_len, avg_len);

  return err;
}
