import sys
import subprocess

NO_OF_PROCESS = 10

def main():
    if(len(sys.argv) < 3):
        print(f"[!] Usage: {sys.argv[0]} <start> <end>")
        exit(0)
    start = int(sys.argv[1], 10)
    end = int(sys.argv[2], 10)
    interval = (end - start) // NO_OF_PROCESS

    for i in range(NO_OF_PROCESS):
        rstart = start + (interval * i)
        rend = rstart + interval
        print(f"[*] Py: Started Process {i} rstart: {rstart} rend: {rend}")
        subprocess.run(["./dbx-crack", str(rstart), str(rend)])

main()