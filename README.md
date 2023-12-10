
# VaultApp

VaultApp is a secure and user-friendly application designed to safeguard your digital assets.

![Logo](https://github.com/sdmdg/vaultapp/assets/151946448/68282bff-03ca-4c43-877b-fd961e1763da)

![img_1](https://github.com/sdmdg/vaultapp/assets/151946448/a5da6b4a-49b8-48d2-8bc1-7604353dd7db)

---

## Features

* Dark mode with a user-friendly UI
* Live previews and thumbnails for common media file types
   - All previews processed in RAM. This approach guarantees the confidentiality of your data.
* AES encryption

![img_2](https://github.com/sdmdg/vaultapp/assets/151946448/eb1405f0-8135-456b-9193-c7341a313b93)

![img_3](https://github.com/sdmdg/vaultapp/assets/151946448/d900087c-46bc-42e2-ab01-d8c91d5a8156)


**Note:** The preview video functionality is currently unavailable. We are actively working on implementing this feature and expect it to be available soon. Thank you for your patience. 🙂

#### Preview Support :

* Images - jpg, png, bmp, jpeg
* Videos - mp4, avi, mkv (coming soon) 🙂

## External Dependencies

* PyQt5
* opencv-python
* numpy
* cryptography (AES encryption)

---

## Installation

1. Install Python 3.11 or above.
2. Clone the repository to your desired location or download the ZIP and extract it.
3. Recommended: Launch `run.bat`(for Windows). This will set up a new virtual environment and install all dependencies.

   **Or**

   - Install dependencies manually using:
     ```bash
     pip install -r requirements.txt
     ```
   - Launch `main.py`.

## Tutorial

1. Create a new password for the vault. The script will generate a new folder ('data') in your current directory, which stores all encrypted files when imported to the vault.
2. Import files to the vault.
3. Enjoy! 🙂

**Note:** For enhanced data privacy, the application does not include an auto-update module. Once it installs all dependencies, it operates offline. Please visit [here](https://github.com/sdmdg/vaultapp/) to manually check for and install updates.

---

## Deleting the Vault

1. First, decrypt and move your files to a secure location.
2. Delete the 'data' folder.

---

## Important Note:

-	**The Authors will not be responsible for any kind of loss of data so it is essential to have a Backup of Original Data you give as Input to Encrypt/Decrypt in the Software. Under no circumstances shall we be liable or responsible to you or any other person for any damages, loss of any of your useful data by using this Software. Read the [LICENSE](https://github.com/sdmdg/vaultapp/blob/master/LICENSE) for more information.**
