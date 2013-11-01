CardAgent-PayPass
=================
Card agent for paypass

CardAgent
=========
The card agent is responsible for being the interface between the mobile application and the 
remote card applet.  the simplytapp libraries allow for an interface to the remote applet.

The card agent is intended to be downloaded at run-time and executed on the handset locally.
It provides messages back to the handset about card status and card requests.  Any communication
to the remote card goes through the card agent and can be preempted by the agent and answered
if the agent deems appropriate.    

Exporting
=========
The card agent class must extend Agent and there should be only one agent extension inside the
resulting jar file.  The jar file should be exported from the project and should be uploaded
to the simplytapp server with the javacard applet jar file.
