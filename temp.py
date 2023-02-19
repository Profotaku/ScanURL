# Ouvrir le fichier en mode lecture
with open('domains0.list.txt', 'r') as f:
    # Lire les lignes du fichier et stocker dans une liste
    lines = f.readlines()

# Ajouter ",bad" à chaque ligne
lines = [line.strip() + ",bad\n" for line in lines]

# Ouvrir le fichier en mode écriture
with open('liste_modifiee.txt', 'w') as f:
    # Écrire les lignes modifiées dans le fichier
    f.writelines(lines)