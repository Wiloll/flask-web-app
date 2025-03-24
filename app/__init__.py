from flask import Flask, request, jsonify, render_template
from keras.models import load_model
import joblib
import os
import numpy as np
import pefile
import h5py
from app.routes import main
import time

app = Flask(__name__)

app.register_blueprint(main)

# Load the model and scaler
model = load_model("D:/Github Repositores/flask-web-app/app/model.h5")
scaler = joblib.load('D:/Github Repositores/flask-web-app/app/scaler.pkl')

def extract_features_from_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        num_sections = len(pe.sections)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        file_alignment = pe.OPTIONAL_HEADER.FileAlignment
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        sections_mean_entropy = np.mean([section.get_entropy() for section in pe.sections])
        return np.array([num_sections, entry_point, image_base, file_alignment, size_of_image, dll_characteristics, sections_mean_entropy])
    finally:
        pe.close()

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    file_path = os.path.join('uploads', file.filename)
    if not os.path.exists(file.filename):
        file.save(file_path)

    retries = 3
    for attempt in range(retries):
        try:
            features = extract_features_from_pe(file_path)
            features_scaled = scaler.transform(features.reshape(1, -1))
            prediction = model.predict(features_scaled)
            result = 'Malicious' if prediction[0] > 0.5 else 'Safe'
            return render_template('base.html', result=result, trigger_js=True)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return jsonify({'error': str(e)}), 500
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)