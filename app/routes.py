from flask import Blueprint, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

# Ensure the upload folder exists

@main.route('/about')
def about():
    return render_template('about.html')

@main.route('/')
def scan():
    return render_template('base.html')