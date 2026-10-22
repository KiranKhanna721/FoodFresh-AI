# FoodFresh AI

FoodFresh AI is a smart food management app that helps users cut food waste and save money by tracking expiry dates with image recognition and AI.

## Features

- **Scan food labels:** upload a photo of a package. OCR (Tesseract) reads the text, and a FLAN-T5 model pulls out the item name and the manufacture and expiry dates.
- **Track your pantry:** each user's items are saved with days left until expiry.
- **Expiry alerts:** see which items are about to expire.
- **User accounts:** sign-up and login stored in SQLite (`data/users.db`).

## Tech stack

Python, Streamlit, pytesseract, Hugging Face Transformers (`google/flan-t5-base`), PyTorch, Pillow, SQLite

## Getting started

1. Install [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) on your system.
2. Install the Python dependencies and run the app:

```bash
pip install -r requirements
streamlit run app.py
```
