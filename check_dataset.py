import os

dataset_folder = "Dataset"

files = os.listdir(dataset_folder)

print("Files inside dataset:")

for file in files:
    print(file)