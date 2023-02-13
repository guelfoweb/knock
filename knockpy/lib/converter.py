def converter(filename: str, output_filename: str) -> None:
    with open(filename, 'r') as file:
        for line in file:
            with open(output_filename, 'a', encoding="utf8") as output_file:
                try:
                    line = line[:-1]
                    line = line.encode("utf8")
                    line = str(line, "utf-8")
                    line = line.encode("idna")
                    print(line)
                    line = line.decode("utf8")
                    output_file.write(line + "\n")
                except UnicodeError:
                    print(line)


if __name__ == "__main__":
    converter("..\\..\\..\\wordlist.txt", "..\\..\\..\\converted.txt")
