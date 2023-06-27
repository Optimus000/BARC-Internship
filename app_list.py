import winapps

file = open("apps_name_list.txt", "w+")

for item in winapps.search_installed():
    file.write(f"{item.name}\n")
file.close()