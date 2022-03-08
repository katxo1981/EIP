# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_domain_info
# Purpose:      Get DNS servers and mails from whois.
#
# Author:      Adrian Martinez Barbudo <katxosls@gmail.com>
#
# Created:     24/02/2022
# Copyright:   (c) Adrian Martinez Barbudo 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

import subprocess

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_domain_info(SpiderFootPlugin):

    meta = {
        'name': "DNS and EMAIL domain_info",
        'summary': "Get DNS servers and mails from whois",
        'flags': [""],
        'useCases': ["Custom"],
        'categories': ["Info"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT", "CO_HOSTED_SITE_DOMAIN", 
                "AFFILIATE_DOMAIN_NAME", "SIMILARDOMAIN"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS","EMAILADDR_GENERIC"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

	# Capturamos la ejecución de whois del dominio suministrado en la variable data
            data = subprocess.run(["whois -I " +eventData], shell=True, capture_output=True, text=True)
            output = str(data.stdout)
            #print (output)

	# separamos por salto de línea
            info = output.split('\n')

	# variables para almlacenar los resultados

            email = list()
            dns = list()

	#recorremos todas las lineas
            for linea in info:
		# separamos por palabras
                palabras = linea.split(' ')
                i=0
		#recorremos todo buscando cadenas de Email y nserver, y las almacenamos
                while i < len(palabras):
                    if palabras[i] == "Email:":
                        print (palabras[i+1])
                        email.append(palabras[i+1])
                    if palabras[i] == "nserver:":
                        print (palabras[i+7])
                        dns.append(palabras[i+7])
                    i+=1        

            #for aux in dns:
                #print(aux)

            if not data:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return

        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

	# recorremos los listados de email e ips de dns servers y los exportamos a spiderfoot

        for aux in dns:
            evt = SpiderFootEvent("IP_ADDRESS", aux, self.__name__, event)
            self.notifyListeners(evt)
        for aux2 in email:
            evt = SpiderFootEvent("EMAILADDR_GENERIC", aux, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_domain_info class