xmpp-client setup
=================

    go get github.com/agl/xmpp-client

(If you don't have Go already installed then see below.)

xmpp-client use
===============

xmpp-client is a simple XMPP client written in pure Go. It's a terminal program and so probably doesn't work on Windows.

xmpp-client expects a config file in `~/.xmpp-client`. You can set the location of the config file with `--config-file` on the command line. If it fails to parse a config file, it'll enter enrollment: where it'll ask a series of questions to configure itself and will then write a config file from the answers.

The config file is just a JSON file and can be edited by hand. (Although xmpp-client will rewrite it, blowing away any comments or custom formatting.)

xmpp-client will prompt for a password each time it's run. If you want to save the password you have to edit the config file and insert a string element called `Password`. (This ensures that you understand that the password is stored in plaintext.)

Once the connection has been established, the commands are quite simple. Type `/help` for a listing.

Messages are sent by entering the JID of a contact and hitting tab to complete the address, followed by a colon. The message can then be entered after the colon, IRC style. Like this:

    > friend@example.com: Hi there!

On subsequent lines you don't have to enter their address again, unless you want to direct messages to someone else:

    > friend@example.com: Hi there!
    > I was thinking
    > about that thing
    > otherfriend@example.com: I'll be right with you!
    > friend@example.com: back again

Messages from others are written in a similar fashion: the address is omitted for subsequent lines and replaced with a colon. The colon is red for unencrypted and green for encrypted.

If a contact name isn't recognised before a colon then it's ignored. Don't assume that you're sending a message to who you think you are unless you tab completed the address.

The client functions, but is very rudimentary.

Installation instructions
=========================

Build and run instructions for Ubuntu 13.10 (codename Saucy Salamander, go version 1.1.2). Note the version of Go shipped with this distro is very old any may be broken now.

    sudo apt-get install git golang mercurial
    export GOPATH=$HOME/go
    go get github.com/agl/xmpp-client
    $GOPATH/bin/xmpp-client

    ## If you want to set up an alias
    echo "alias xmpp-client='$GOPATH/bin/xmpp-client' " >> ~/.bashrc
    . ~/.bashrc
    xmpp-client

Build and run instructions for Tails (tested on version 1.2, go version 1.2)

    ## If you don't have already
    sudo apt-get update
    
    ## Debian old-stable, on which Tails is currently based, doesn't have Go packages
    sudo apt-get install -t unstable golang

    ## Git is already included in tails so we only need to get Mercurial
    sudo apt-get install mercurial

    ## Assuming you have created a persistant volume
    export GOPATH=/home/amnesia/Persistent/go/

    go get github.com/agl/xmpp-client
    $GOPATH/bin/xmpp-client
