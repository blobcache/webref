# WebRefs

WebRefs are general purpose references to data, available over the network, in the filesystem etc.
They extend the concept of a URL to include read-time transformations on the data being retrieved.
This allows encryption, compression, and cryptographic checksumming to be performed on the data.

This project evolved out of the WebRefs in [WebFS](https://github.com/brendoncarroll/webfs)
Blobcache uses WebRefs to index externally available data.
