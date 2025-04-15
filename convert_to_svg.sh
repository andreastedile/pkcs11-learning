for file in known_attacks/wrap_and_decrypt/*.dot; do dot -Tsvg "$file" -o "${file%.dot}.svg"; done
for file in known_attacks/dks_2/*.dot; do dot -Tsvg "$file" -o "${file%.dot}.svg"; done
for file in known_attacks/dks_3/*.dot; do dot -Tsvg "$file" -o "${file%.dot}.svg"; done
for file in known_attacks/dks_6/*.dot; do dot -Tsvg "$file" -o "${file%.dot}.svg"; done
for file in known_attacks/fls2/*.dot; do dot -Tsvg "$file" -o "${file%.dot}.svg"; done
