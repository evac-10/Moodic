import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import pandas as pd
import time

# Initialize Spotipy client
auth_manager = SpotifyClientCredentials(client_id='f8b47a9716d24616b203466a7cc0bda3', client_secret='eb9ba802751d4551b87cbaa321af1a74')
sp = spotipy.Spotify(auth_manager=auth_manager)

# Function to get track IDs from a playlist
def getTrackIDs(user, playlist_id):
    track_ids = []
    playlist = sp.playlist_tracks(playlist_id)
    for item in playlist['items']:
        track = item['track']
        track_ids.append(track['id'])
    return track_ids

# Function to get track features
def getTrackFeatures(id):
    track_info = sp.track(id)
    name = track_info['name']
    album = track_info['album']['name']
    artist = track_info['album']['artists'][0]['name']
    return name, album, artist

# Function to fetch tracks from a playlist and save to CSV
def fetch_playlist_tracks(emotion_name, playlist_id):
    track_ids = getTrackIDs('spotify', playlist_id)
    track_list = []
    for track_id in track_ids:
        time.sleep(0.5)  # Add a delay to avoid rate limiting
        track_data = getTrackFeatures(track_id)
        track_list.append(track_data)
    df = pd.DataFrame(track_list, columns=['Name', 'Album', 'Artist'])
    df.to_csv(f'songs/{emotion_name}.csv', index=False)
    print(f"CSV Generated for {emotion_name} playlist")

# Dictionary containing emotion names and their corresponding playlist IDs
emotion_playlists = {
    'Angry': '0l9dAmBrUJLylii66JOsHB',
    'Disgusted': '1n6cpWo9ant4WguEo91KZh',
    'Fearful': '4cllEPvFdoX6NIVWPKai9I',
    'Happy': '0deORnapZgrxFY4nsKr9JA',
    'Neutral': '4kvSlabrnfRCQWfN0MgtgA',
    'Sad': '1n6cpWo9ant4WguEo91KZh',
    'Surprised': '37i9dQZEVXbMDoHDwVN2tF'
}

# Fetch tracks for each emotion playlist and save to CSV
for emotion, playlist_id in emotion_playlists.items():
    fetch_playlist_tracks(emotion, playlist_id)
