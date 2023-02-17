def converter(filename: str, output_filename: str) -> None:
    with open(filename, 'r', encoding="utf-8", newline="") as file:
        for line in file:
            with open(output_filename, 'a', encoding="utf8") as output_file:
                try:
                    line = line[:-1]
                    line = line.encode("utf8")
                    line = str(line, "utf-8")
                    line = line.encode("idna")
                    line = line.decode("utf8")
                    output_file.write(line + "\n")
                except UnicodeDecodeError:
                    print(line)
