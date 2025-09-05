

from pathlib import Path


def load_url_account_list(file_path: str, account: str) -> list[str]:
    txt_file = Path(file_path)
    if not txt_file.is_file() or not txt_file.exists():
        raise FileNotFoundError(f"URL list file not found: {file_path}")

    url_lines = txt_file.read_text().splitlines()

    urls: list[str] = []
    for line in url_lines:
        line = line.strip()
        if "{account}" not in line:
            print(f"Skipping line without '{{account}}' placeholder: {line}")
            continue

        line = line.format(account=account)
        urls.append(line)

    return urls

