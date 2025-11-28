package sniffers_utilits

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func GetWebInterface(networkShell string) (handle *pcap.Handle) {
	handle, err := pcap.OpenLive(networkShell, 1600, true, time.Second)

	if err != nil {
		log.Fatal(err)
	}

	if handle == nil {
		log.Fatal("handle error: hendle is null!")
	}

	return handle
}
func CreateNewPackets(handle *pcap.Handle) (packet *gopacket.PacketSource) {
	packet = gopacket.NewPacketSource(handle, handle.LinkType())
	return packet
}
