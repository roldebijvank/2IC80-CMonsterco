# This script will clear and populate the user's Documents, Videos, Downloads, Desktop, Music, and Pictures folders
# with at least 1GB of data each.
import os
import shutil
import random
import string
from pathlib import Path

def get_user_folders():
	from os.path import expanduser, join
	user = expanduser('~')
	folders = [
		join(user, 'Documents'),
		join(user, 'Videos'),
		join(user, 'Downloads'),
		join(user, 'Desktop'),
		join(user, 'Music'),
		join(user, 'Pictures'),
	]
	return [Path(f) for f in folders]

def clear_folder(folder: Path):
	if not folder.exists():
		return
	for item in folder.iterdir():
		try:
			if item.is_file() or item.is_symlink():
				item.unlink()
			elif item.is_dir():
				shutil.rmtree(item)
		except Exception as e:
			print(f"Failed to remove {item}: {e}")


def write_gb_of_data(folder: Path, min_gb: int = 1):
	# Write text files as fast as possible by writing a repeated static string in large chunks
	bytes_per_gb = 1024 * 1024 * 1024
	total_bytes = 0
	file_index = 0
	chunk_size = 64 * 1024 * 1024  # 64MB per write for speed
	static_chunk = ("A" * chunk_size)
	while total_bytes < min_gb * bytes_per_gb:
		file_size = min(bytes_per_gb // 2, (min_gb * bytes_per_gb) - total_bytes)  # up to 512MB per file
		file_path = folder / f"dummy_{file_index}.txt"
		written = 0
		with open(file_path, 'w', encoding='utf-8') as f:
			while written < file_size:
				to_write = min(chunk_size, file_size - written)
				f.write(static_chunk[:to_write])
				written += to_write
		total_bytes += file_size
		file_index += 1
		print(f"Wrote {file_path} ({file_size} bytes), total: {total_bytes}")

def main():
	folders = get_user_folders()
	for folder in folders:
		print(f"Processing {folder}...")
		folder.mkdir(parents=True, exist_ok=True)
		clear_folder(folder)
		write_gb_of_data(folder, min_gb=1)
		print(f"Done with {folder}\n")

if __name__ == "__main__":
	main()
