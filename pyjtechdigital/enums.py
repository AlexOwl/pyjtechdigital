from enum import Enum

class Scaler(Enum):
    Bypass = 0
    ScaleDown = 1
    Auto = 3

class CECSourceCommand(Enum):
    TurnOn = 1
    TurnOff = 2
    KeyUp = 3
    KeyLeft = 4
    Center = 5
    KeyRight = 6
    Menu = 7
    KeyDown = 8
    Back = 9
    Prev = 10
    Play = 11
    Next = 12
    Rewind = 13
    Pause = 14
    Forward = 15
    Stop = 16
    Mute = 17
    VolumeDown = 18
    VolumeUp = 19

class CECOutputCommand(Enum):
    TurnOn = 0
    TurnOff = 1
    Mute = 2
    VolumeDown = 3
    VolumeUp = 4
    Source = 5

class BaudrateIndex(Enum):
    Baudrate4800 = 1
    Baudrate9600 = 2
    Baudrate19200 = 3
    Baudrate38400 = 4
    Baudrate57600 = 5
    Baudrate115200 = 6

class EdidResolution(Enum):
    Resolution1080P = 0
    Resolution1080I = 1
    Resolution3D = 2
    Resolution4K2K30_444 = 3
    Resolution4K2K60_420 = 4
    Resolution4K2K60_444 = 5

class EdidAudio(Enum):
    StereoAudio20 = 0
    DolbyDTS51 = 1
    HDAudio71 = 2

class EdidIndex(Enum):
    Resolution1080P_StereoAudio20 = 0
    Resolution1080P_DolbyDTS51 = 1
    Resolution1080P_HDAudio71 = 2
    Resolution1080I_StereoAudio20 = 3
    Resolution1080I_DolbyDTS51 = 4
    Resolution1080I_HDAudio71 = 5
    Resolution3D_StereoAudio20 = 6
    Resolution3D_DolbyDTS51 = 7
    Resolution3D_HDAudio71 = 8
    Resolution4K2K30_444_StereoAudio20 = 9
    Resolution4K2K30_444_DolbyDTS51 = 10
    Resolution4K2K30_444_HDAudio71 = 11
    Resolution4K2K60_420_StereoAudio20 = 12
    Resolution4K2K60_420_DolbyDTS51 = 13
    Resolution4K2K60_420_HDAudio71 = 14
    Resolution4K2K60_444_StereoAudio20 = 15
    Resolution4K2K60_444_DolbyDTS51 = 16
    Resolution4K2K60_444_HDAudio71 = 17
    Resolution4K2K60_444_StereoAudio20_HDR = 18
    Resolution4K2K60_444_DolbyDTS51_HDR = 19
    Resolution4K2K60_444_HDAudio71_HDR = 20
    UserDefine1 = 21
    UserDefine2 = 22
    CopyFromHDMI1 = 23
    CopyFromHDMI2 = 24
    CopyFromHDMI3 = 25
    CopyFromHDMI4 = 26
    CopyFromCAT1 = 27
    CopyFromCAT2 = 28
    CopyFromCAT3 = 29
    CopyFromCAT4 = 30