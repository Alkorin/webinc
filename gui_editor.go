package main

import (
	"github.com/jroimartin/gocui"
)

type HistoryEditor struct {
	history            []string
	currentHistoryLine int
	callback           func(string)
}

func NewHistoryEditor(cb func(string)) *HistoryEditor {
	return &HistoryEditor{
		history:  []string{""},
		callback: cb,
	}
}

func (h *HistoryEditor) Edit(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	switch {
	case ch != 0 && mod == 0:
		v.EditWrite(ch)
	case key == gocui.KeySpace:
		v.EditWrite(' ')
	case key == gocui.KeyBackspace || key == gocui.KeyBackspace2:
		v.EditDelete(true)
	case key == gocui.KeyDelete:
		v.EditDelete(false)
	case key == gocui.KeyInsert:
		v.Overwrite = !v.Overwrite
	case key == gocui.KeyArrowLeft:
		v.MoveCursor(-1, 0, false)
	case key == gocui.KeyArrowRight:
		v.MoveCursor(1, 0, false)
	case key == gocui.KeyHome || key == gocui.KeyCtrlA:
		v.SetCursor(0, 0)
	case key == gocui.KeyEnd || key == gocui.KeyCtrlE:
		v.SetCursor(0, 0)
		if lines := v.BufferLines(); len(lines) == 1 {
			v.MoveCursor(len(lines[0]), 0, true)
		}
	case key == gocui.KeyCtrlK:
		if lines := v.BufferLines(); len(lines) == 1 {
			x, _ := v.Cursor()
			data := lines[0][:x]
			v.Clear()
			v.SetCursor(0, 0)
			v.Write([]byte(data))
			v.MoveCursor(len(data), 0, true)
		}
	case key == gocui.KeyCtrlU:
		if lines := v.BufferLines(); len(lines) == 1 {
			x, _ := v.Cursor()
			data := lines[0][x:]
			v.Clear()
			v.SetCursor(0, 0)
			v.Write([]byte(data))
			v.MoveCursor(len(data), 0, true)
		}
	case key == gocui.KeyArrowDown:
		if h.currentHistoryLine < len(h.history)-1 {
			// Save current line
			if lines := v.BufferLines(); len(lines) == 1 {
				h.history[h.currentHistoryLine] = lines[0]
			}
			h.currentHistoryLine++
			v.Clear()
			v.SetCursor(0, 0)
			v.Write([]byte(h.history[h.currentHistoryLine]))
			v.MoveCursor(len(h.history[h.currentHistoryLine]), 0, true)
		}
	case key == gocui.KeyArrowUp:
		if h.currentHistoryLine > 0 {
			// Save current line
			if lines := v.BufferLines(); len(lines) == 1 {
				h.history[h.currentHistoryLine] = lines[0]
			}
			h.currentHistoryLine--
			v.Clear()
			v.SetCursor(0, 0)
			v.Write([]byte(h.history[h.currentHistoryLine]))
			v.MoveCursor(len(h.history[h.currentHistoryLine]), 0, true)
		}
	case key == gocui.KeyEnter:
		if lines := v.BufferLines(); len(lines) == 1 {
			line := lines[0]
			h.callback(line)
			h.history[len(h.history)-1] = line
			h.history = append(h.history, "")
			h.currentHistoryLine = len(h.history) - 1
			v.Clear()
			v.SetCursor(0, 0)
		}
	}
}
