import webbrowser
from app import app
import threading

def open_browser():
    # Wait a bit for the server to start before opening the browser
    webbrowser.open_new('http://127.0.0.1:5000/')

if __name__ == "__main__":
    # Start the browser in a separate thread
    threading.Timer(1, open_browser).start()
    app.run(debug=True)
