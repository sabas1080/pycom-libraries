""" LoPy LoRaWAN Nano Gateway example usage """

import config
from nanogateway import NanoGateway


nanogw = NanoGateway(id=config.GATEWAY_ID, frequency=config.LORA_FREQUENCY,
                     datarate=config.LORA_DR, server=config.SERVER,
                     port=config.PORT)

nanogw.start()
