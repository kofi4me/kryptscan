$env:PYTHONPATH = ".python_packages"
python -m uvicorn app.main:app --reload
