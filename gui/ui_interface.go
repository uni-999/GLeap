package gui

import (
	"encoding/csv"
	"os"
	"strings"
	"sync/atomic"
	"uni-999/go/gleap/sniffers_utilits"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket/layers"
)

var networkShell string
var DATA = [][]string{
	{"Время захвата", "Source IP", "Destination IP", "Порты", "Флаги TCP"},
}

func BaseInterface() {
	GLEAP := app.New()
	mainWindow := GLEAP.NewWindow("GLEAP")

	selectEthernetShell := widget.NewRadioGroup([]string{"en0", "en1", "unut0"}, func(selected string) {
		networkShell = selected
	})

	table := widget.NewTable(
		func() (int, int) {
			return len(DATA), len(DATA[0])
		},
		func() fyne.CanvasObject {
			lbl := widget.NewLabel("")
			lbl.Wrapping = fyne.TextWrapWord
			lbl.Alignment = fyne.TextAlignCenter
			return container.NewPadded(lbl)
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*fyne.Container).Objects[0].(*widget.Label)
			label.SetText(DATA[id.Row][id.Col])
		},
	)

	table.SetColumnWidth(0, 130)
	table.SetColumnWidth(1, 130)
	table.SetColumnWidth(2, 130)
	table.SetColumnWidth(3, 120)
	table.SetColumnWidth(4, 150)

	var stopSniffing int32
	menuBar := container.NewHBox(
		newPopupMenuButton(mainWindow, "Файл", map[string]func(){
			"Открыть":   func() { openFileDialog(mainWindow, table) },
			"Сохранить": func() { saveFileDialog(mainWindow) },
			"Выход":     func() { GLEAP.Quit() },
		}),
		newPopupMenuButton(mainWindow, "Сниффер", map[string]func(){
			"Запустить": func() {
				sniffingProcess(&stopSniffing, table)
			},
			"Остановить": func() {
				atomic.StoreInt32(&stopSniffing, 1)
			},
		}),
		newPopupMenuButton(mainWindow, "Справка", map[string]func(){
			"О программе": func() {},
		}),
	)

	mainWindow.SetContent(
		container.NewBorder(
			container.NewVBox(
				menuBar,
				selectEthernetShell,
			),
			nil, nil, nil,
			table,
		),
	)

	mainWindow.Resize(fyne.NewSize(700, 500))
	mainWindow.ShowAndRun()
}
func checkTcpFlags(tcpFlags *layers.TCP) string {
	if tcpFlags == nil {
		return ""
	}
	flags := []string{}
	if tcpFlags.FIN {
		flags = append(flags, "FIN")
	}
	if tcpFlags.SYN {
		flags = append(flags, "SYN")
	}
	if tcpFlags.RST {
		flags = append(flags, "RST")
	}
	if tcpFlags.PSH {
		flags = append(flags, "PSH")
	}
	if tcpFlags.ACK {
		flags = append(flags, "ACK")
	}
	if tcpFlags.URG {
		flags = append(flags, "URG")
	}
	if tcpFlags.ECE {
		flags = append(flags, "ECE")
	}
	if tcpFlags.CWR {
		flags = append(flags, "CWR")
	}
	if tcpFlags.NS {
		flags = append(flags, "NS")
	}
	return strings.Join(flags, ", ")
}
func newPopupMenuButton(window fyne.Window, title string, actions map[string]func()) *widget.Button {
	btn := widget.NewButton(title, func() {})

	btn.OnTapped = func() {
		menuItems := make([]*fyne.MenuItem, 0)
		for itemName, handler := range actions {
			handlerCopy := handler
			menuItems = append(menuItems, fyne.NewMenuItem(itemName, handlerCopy))
		}

		menu := fyne.NewMenu("", menuItems...)
		pop := widget.NewPopUpMenu(menu, window.Canvas())
		pos := fyne.NewPos(btn.Position().X, btn.Position().Y+btn.Size().Height)
		pop.ShowAtPosition(pos)
	}

	return btn
}
func saveFileDialog(window fyne.Window) {
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()

		file, err := os.Create(writer.URI().Path())
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		defer file.Close()

		w := csv.NewWriter(file)
		err = w.WriteAll(DATA)
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		w.Flush()
		dialog.ShowInformation("Сохранено", "Файл успешно сохранён.", window)
	}, window)
}
func openFileDialog(window fyne.Window, table *widget.Table) {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		defer reader.Close()

		file, err := os.Open(reader.URI().Path())
		if err != nil {
			dialog.ShowError(err, window)
			return
		}
		defer file.Close()

		r := csv.NewReader(file)
		data, err := r.ReadAll()
		if err != nil {
			dialog.ShowError(err, window)
			return
		}

		if len(data) > 0 {
			DATA = data
			table.Refresh()
			dialog.ShowInformation("Загружено", "Данные успешно загружены.", window)
		}
	}, window)
}
func sniffingProcess(stopSniffing *int32, table *widget.Table) {
	if networkShell == "" {
		fyne.CurrentApp().SendNotification(&fyne.Notification{
			Title:   "Ошибка",
			Content: "Выберите сетевой интерфейс перед запуском.",
		})
		return
	}

	atomic.StoreInt32(stopSniffing, 0)
	go func() {
		handle := sniffers_utilits.GetWebInterface(networkShell)
		defer handle.Close()
		packetSource := sniffers_utilits.CreateNewPackets(handle)

		for packets := range packetSource.Packets() {
			if atomic.LoadInt32(stopSniffing) == 1 {
				break
			}

			ipLayer := packets.Layer(layers.LayerTypeIPv4)
			tcpLayer := packets.Layer(layers.LayerTypeTCP)

			if ipLayer == nil || tcpLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)

			newRow := []string{
				packets.Metadata().Timestamp.Format("15:04:05"),
				ip.SrcIP.String(),
				ip.DstIP.String(),
				tcp.SrcPort.String() + " → " + tcp.DstPort.String(),
				checkTcpFlags(tcp),
			}
			DATA = append(DATA, newRow)
			table.Refresh()
		}
	}()
}
