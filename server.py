from flask import Flask, redirect, render_template, request, url_for
from flask_socketio import SocketIO, emit

from message import Message
from secret import alice, bob, messages
from user import User

app = Flask(__name__, static_url_path="", static_folder="web/static")
app.config["SECRET_KEY"] = "secret!"
socketio = SocketIO(app)

available_users = {"alice": alice, "bob": bob}


@app.route("/")
def index():
    return render_template("index.html", available_users=available_users)


@app.route("/logout/<user_name>")
def logout(user_name: str):
    if user_name == "alice":
        available_users[user_name] = alice
    elif user_name == "bob":
        available_users[user_name] = bob
    return redirect("/")


@app.route("/<user_name>")
def select_user(user_name: str):
    if user_name == "favicon.ico":
        return redirect("/")

    # user = available_users.pop(user_name)
    return redirect(url_for(f"get_messages", user_name=user_name))


@app.route("/<user_name>/messages")
def get_messages(user_name: str):
    user = available_users[user_name]

    return render_template(
        "messages.html", user_name=user_name, user=user, messages=messages
    )


@socketio.on("connect")
def handle_connect():
    print(f"Client connected")


@socketio.on("user_join")
def handle_user_join(username):
    print(f"{username} joined")


@socketio.on("message")
def handle_message(data):
    author = data["author"]
    payload = data["payload"]

    #Todo: encrypt message
    message = Message(author, payload)
    messages.append(message)

    print(f"NEW MESSAGE: {author}: {payload}")
    emit("message", {"author": author, "payload": payload + "+++"}, broadcast=True)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port="1234", debug=True)
