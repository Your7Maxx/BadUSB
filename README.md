# BadUSB
Detecting and blocking demo in badusb scenario based on KRSI.

## Introduce
Before you start testing, Make sure your system has bcc and its environment installed.


Before you start testing, check the Vendor ID and Product ID of your hid device and update them in the corresponding fields in the `rule.json` file. This file holds the whitelist of all hid devices, and the rule action is allow registration. Second, the `hidtypes.json` configuration file stores the correspondence between the type code of the hid device event and the actual device type. The `keycode.json` configuration file stores the mapping between keycode codes and actual user input.

## Useage
### hid device register monitor & interdict

```
./detect.py
```
![Image text](https://github.com/Your7Maxx/BadUSB/blob/main/hidregister.png?raw=true)
```
int('2341', 16) = 9025  //vendorID
int('8036', 16) = 32822 //productID
```
### hid device keycode input monitor
```
./keycode.py
```
![Image text](https://github.com/Your7Maxx/BadUSB/blob/main/keycode.png?raw=true)
