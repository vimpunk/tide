# Tide

Tide will eventually be a fully documented, feature-complete, fast, and easy to use BitTorrent library, written in modern C++ (14 or 17, depending on when 1.0 is launched) to serve as the underlying engine for BitTorrent applications.
For now, though usable, it is unstable. Features are added, bugs fixed, and API changes are made on a regular basis.

## NOTE

Although it doesn't currently work, you can run Tide by executing the following steps:
- install Asio (the standalone version) and Boost (though I'm aiming to remove this dependency),
- cd to the `build` directory,
- execute
```
cmake build -DCMAKE_INSTALL_PREFIX=/usr ..
sudo make install -j
```
(which will build the library and install the necessary header files to `/usr/include`)
- then simply include tide by specifying `#include <tide.hpp>` in your source code.
- and compile it with: `g++ -std=c++17 your_app.cpp -ltide -lpthread -lcrypto -lstdc++fs -lboost_system`.
