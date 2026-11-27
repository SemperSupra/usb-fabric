/* Read real Linux input_event records; no synthetic guest events. */
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    if (fd < 0) return 3;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("GUEST_EVDEV_READY");
    int down = 0;
    for (int i = 0; i < 100; ++i) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int n = poll(&p, 1, 1000);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) continue;
        struct input_event e;
        ssize_t got = read(fd, &e, sizeof(e));
        if (got != sizeof(e)) continue;
        if (e.type != EV_KEY || e.code != KEY_A) continue;
        if (e.value == 1 && !down) {
            puts("GUEST_EVDEV_KEY_A_DOWN=PASS");
            down = 1;
        } else if (e.value == 0 && down) {
            puts("GUEST_EVDEV_KEY_A_UP=PASS");
            close(fd);
            return 0;
        }
    }
    close(fd);
    puts("GUEST_EVDEV_TIMEOUT");
    return 4;
}
