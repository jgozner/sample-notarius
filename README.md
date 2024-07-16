# sign-pdf-with-notarius

Require: python version 3.9 or higher

Create venv
```
python3 -m venv venv
```

Active venv
```
source venv/bin/activate
```
Install package
```
pip install -m requirements.txt
```
Install apryse sdk
```
pip install apryse-sdk --extra-index-url=https://pypi.apryse.com
```
Create .env and paste the environment from 1password 
```
vim .env
```
Run 
```
python3 main.py
```

### Notarius API docs: 
- https://support.notarius.com/wp-content/uploads/api/h2-api-en.html#

### Apryse code following:
- https://docs.apryse.com/documentation/samples/py/DigitalSignaturesTest?platforms=python
- https://docs.apryse.com/documentation/core/guides/features/signature/custom-signing/
- https://github.com/jgozner/azure-hsm-signing/blob/main/Program.cs

### PDF files
Original: letter.pdf
Signed: signed.pdf
Signed correctly example from notarius: correct.pdf

For .env, please contact long.quach@blueink.com