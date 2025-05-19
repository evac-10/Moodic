# Emotion-Music-Recommendation

## Table of Contents
- [Project Description](#project-description)
- [Features](#features)
- [Running the App](#running-the-app)
- [Tech Stack](#tech-stack)
- [Dataset](#dataset)
- [Model Architecture](#model-architecture)
- [Image Processing and Training](#image-processing-and-training)
- [Current Condition](#current-condition)
- [Project Components](#project-components)

## Project Description
The Emotion-Music-Recommendation project utilizes real-time facial expression detection to recommend music based on the detected emotion. It integrates the FER 2013 dataset for emotion recognition and the Spotify API for fetching playlists. The application captures live video feed from the webcam, processes it through a trained model to predict the user's emotion, and then suggests relevant playlists from Spotify.

## Features
- Real-time expression detection and song recommendations.
- Playlists fetched from Spotify using the API.

## Running the App
**Flask:**
- Run `pip install -r requirements.txt` to install all dependencies.
- In `Spotipy.py`, enter your Spotify Developer account credentials in the 'auth_manager' section. Note: This is only required if you want to update recommendation playlists. Also, uncomment the import statement in `camera.py`.
- Run `python app.py` and grant camera permission if asked.

## Tech Stack
- Keras
- Tensorflow
- Spotipy
- Tkinter (For testing)
- Flask

## Dataset
The project utilizes the FER2013 dataset, which contains images labeled with 7 different emotions. You can find the dataset [here](https://www.kaggle.com/msambare/fer2013).

Note: The dataset is imbalanced, with the "happy" class having the maximum representation.

## Model Architecture
- The model architecture consists of Conv2D, MaxPooling2D, Dropout, and Dense layers.
- Conv2D layers have filter sizes ranging from 32 to 128, all with 'relu' activation.
- Pooling layers have a pool size of (2,2).
- Dropout is set to 0.25 to prevent overfitting.
- The final Dense layer uses 'softmax' activation for classifying 7 emotions.
- It uses 'categorical_crossentropy' loss and the 'Adam' optimizer with the 'accuracy' metric.

## Image Processing and Training
- Images are normalized, resized to (48,48), and converted to grayscale in batches of 64 using the 'ImageDataGenerator' in Keras.
- Training took approximately 13 hours locally for 75 epochs with an accuracy of around 66%.

## Current Condition
The project is fully functional, with live detection providing good frame rates due to multithreading.

## Project Components
- Spotipy: Module for connecting to Spotify and fetching tracks using Spotipy wrapper.
- Haarcascade: For face detection.
- camera.py: Module for video streaming, frame capturing, prediction, and recommendation passed to `main.py`.
- main.py: Main Flask application file.
- index.html: Web page for the application, containing basic HTML and CSS.
- utils.py: Utility module for webcam video streaming with threads for real-time detection.
- train.py: Script for image processing and training the model.
