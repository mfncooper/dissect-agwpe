# AGWPE Dissector

A comprehensive Wireshark dissector for the
[AGWPE protocol](https://www.on7lds.net/42/sites/default/files/AGWPEAPI.HTM),
written in Lua.

This dissector breaks down the header of an AGWPE frame into its component
fields, and, for frames that include additional data, breaks down that data
into its own component parts.

**Author**: Martin F N Cooper, KD6YAM  
**License**: MIT License

## Usage

### Get the script

There are several options for how to get the script. Here are a few:

- With your browser open at the [GitHub repository](https://github.com/mfncooper/dissect-agwpe),
  do one of the following:
  - Click on the `agwpe.lua` file in the list to open it, and then click the
   'Download raw file' button on the right of the file header.
  - Click the down-arrow on the right of the green 'Code' button, and then
    choose Download ZIP. Unzip the file after downloading to obtain the
    `agwpe.lua` file (and the README file).
- From the command line, use `wget`, `curl`, or an equivalent tool to retrieve
  the file from the following URL:
  `https://raw.githubusercontent.com/mfncooper/dissect/refs/heads/main/agwpe.lua`
- Using any Git client on your computer, clone the repository using the web URL
  shown when you click the green 'Code' button.

### Copy it to Wireshark

To have Wireshark use the dissector, the script must be copied into one of
Wireshark's plugin folders, either personal (available to the current user
only), or global (available to all users of your computer).

To locate the appropriate folder, in Wireshark, go to:

    Help -> About Wireshark -> Folders

Look for either Personal Lua Plugins or Global Lua Plugins, as appropriate.

Copy the `agwpe.lua` file to the appropriate folder. Note that the folder may
not yet exist, so you may need to create it first.

### Set your server port

The AGWPE dissector needs to be able to determine the direction in which AGWPE
frames are flowing, so that it can distinguish between requests and responses.
To tell the dissector which port your AGWPE server is listening on, you need
to set the `Server port` preference. See [Preferences] below.

### Notes

- If you do not see any AGWPE protocol elements in the Wireshark Packet List,
  make sure that you have the server port set correctly, so that the dissector
  can recognize the frames.
- When sending frames that include data, some AGWPE implementations send a
  single TCP packet including both header and data, while others send the
  header and then the data in separate packets. This scenario is detected by
  Wireshark and the packets are reassembled into one unit. When this happens,
  you will see TCP packets marked with "\[TCP segment of a reassembled PDU\]".
  These messages are normal, and can be safely ignored.
- Some AGWPE implementations will, at times, send multiple AGWPE frames in a
  single TCP packet. When this happens, you will find multiple AGWPE entries
  shown under a single TCP entry in the Wireshark Packet Details pane. If you
  need to see the breakdown of the frame sizes, you will find each PDU size
  listed within the TCP entry, together with the total payload size.

## Preferences

The following preferences may be set in Wireshark by going to:

    Edit -> Preferences -> Protocols -> AGWPE

<dl>
  <dt>Server port (default: 8000)</dt>
  <dd>Used to determine whether a frame is a request or response, which in turn
    allows correct interpretation of the data kind field. This must be set
    correctly for the dissector to work properly.</dd>
  <br>
  <dt>Strict validation (default: enabled)</dt>
  <dd>When true, the reserved fields of a possible header are checked for
    compliance with the AGWPE spec before dissecting and showing the header.
    When false, reserved fields are ignored, which can be useful when working
    with a non-compliant client or server. However, it can also lead to false
    positives and incorrect identification of AGWPE frames.</dd>
  <br>
  <dt>Show reserved fields (default: disabled)</dt>
  <dd>When true, every field in a header is shown, including the reserved
    fields, which should always be zeroed out per the AGWPE spec. This option
    can be useful when Strict validation is disabled, in order to examine
    the details of a non-compliant header.</dd>
</dl>
