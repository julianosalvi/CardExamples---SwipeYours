CardApplet-VisaMSD--SwipeYours-
===============================

Javacard Applet for functioning visa contactless MSD credential


Dependencies
============
This package requires the SimplyTapp STSE libraries to build and simulate with your project.
please find them at www.simplytapp.com free of charge


About
=====
The javacard code included does NOT represent an official Visa card applet.  It is relegated to MSD functionality
and will answer to any reader that requests VISA contactless cards.  The applet can be personalized with 
any track 2 data from a magnetic stripe card and used to deliver that data to the NFC POS terminal


Personalization Script for simulator or gpjNG
=============================================
#card manager
/card
auth

#change the keys to the security domain
put-key -m add 1/1/DES/ffffffffffffffffffffffffffffffff 1/2/DES/ffffffffffffffffffffffffffffffff 1/3/DES/ffffffffffffffffffffffffffffffff

#delete applets if they are already there
delete -r a0000000031010
delete -r 325041592e5359532e4444463031

#install the applets
install -i a0000000031010 -q C9#() 636f6d2e7374 436172644170706c6574
install -i 325041592e5359532e4444463031 -q C9#() 636f6d2e7374 5070736532506179

#perso
/select a0000000031010
/send 00e20000$T200

/atr
/select 325041592e5359532e4444463031
/select a0000000031010

Perso script note
=================
where $T2 represents the track 2 data of a card to emulate at the NFC POS.
the $T2 should include the length value in bytes of the preceding data. e.g.:
115444444444444444D1411101229055018F
parsed:
Len = 11  (length = 17 bytes)
Pan = 5444444444444444 (8 bytes)
T2 delimiter(=) = D (1 nibble)
Exp = 1411 (expiry YYMM 2 bytes)
SC = 101 (3 nibbles)
DD = 229055018 (9 nibbles)
Pad = F (1 nibble)


Exporting
=========
the card applet should be exported to a jar file.  the jar file should be exported from the project and should 
be uploaded to the simplytapp server with the card agent jar file.


 