package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/jroimartin/gocui"
)

type GoCUI struct {
	*gocui.Gui
	conversation *Conversation

	spacesMutex       sync.RWMutex
	spacesMap         map[string]int
	spacesList        []GuiSpace
	currentSpaceIndex int
}

type GuiSpace struct {
	*Space
	Highlight  bool
	NewMessage bool
}

func (g *GuiSpace) DisplayName() string {
	name := g.Space.DisplayName
	if g.Team != nil {
		name = g.Team.DisplayName + "/" + name
	}
	return name

}

func NewGoCUI(c *Conversation) (*GoCUI, error) {
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return nil, err
	}

	gui := &GoCUI{
		Gui:          g,
		conversation: c,
		spacesMap:    make(map[string]int),
	}
	gui.Cursor = true
	gui.SetManagerFunc(gui.layout)

	if err := gui.keybindings(gui.Gui); err != nil {
		return nil, err
	}

	c.AddNewSpaceEventHandler(gui.NewSpaceHandler)
	c.AddNewActivityEventHandler(gui.NewActivityHandler)

	return gui, nil
}

func (gui *GoCUI) Start() error {
	if err := gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		return err
	}
	gui.Close()
	return nil
}

func (gui *GoCUI) NewSpaceHandler(s *Space) {
	gui.spacesMutex.Lock()
	pos := len(gui.spacesList)
	gui.spacesList = append(gui.spacesList, GuiSpace{Space: s})
	gui.spacesMap[s.Id] = pos
	gui.spacesMutex.Unlock()

	gui.updateSpaceList()
}

func (gui *GoCUI) NewActivityHandler(s *Space, a *Activity) {
	gui.spacesMutex.RLock()
	defer gui.spacesMutex.RUnlock()

	if a.Verb == "post" {
		spaceIndex := gui.spacesMap[s.Id]
		if spaceIndex != gui.currentSpaceIndex {
			gui.spacesList[spaceIndex].NewMessage = true
			for _, v := range a.Object.Mentions.Items {
				if v.Id == gui.conversation.device.UserID {
					gui.spacesList[spaceIndex].Highlight = true
				}
			}
			gui.updateSpaceList()
		} else {
			gui.updateMessages()
		}
	}
}

func (gui *GoCUI) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (gui *GoCUI) keybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, gui.quit); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyCtrlN, gocui.ModNone, gui.nextSpace); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyCtrlP, gocui.ModNone, gui.previousSpace); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyEnter, gocui.ModNone, gui.sendMessage); err != nil {
		return err
	}
	return nil
}

func (gui *GoCUI) nextSpace(g *gocui.Gui, v *gocui.View) error {
	gui.moveToSpace(gui.currentSpaceIndex + 1)
	return nil
}

func (gui *GoCUI) previousSpace(g *gocui.Gui, v *gocui.View) error {
	gui.moveToSpace(gui.currentSpaceIndex - 1)
	return nil
}

func (gui *GoCUI) moveToSpace(i int) {
	gui.spacesMutex.RLock()
	defer gui.spacesMutex.RUnlock()

	// Wrap
	if i < 0 {
		i = len(gui.spacesList) - 1
	} else if i >= len(gui.spacesList) {
		i = 0
	}

	gui.currentSpaceIndex = i
	// Reset flags
	gui.spacesList[i].NewMessage = false
	gui.spacesList[i].Highlight = false
	// Refresh
	gui.updateSpaceStatus()
	gui.updateSpaceList()
	gui.updateMessages()
}

func (gui *GoCUI) sendMessage(g *gocui.Gui, v *gocui.View) error {
	gui.spacesMutex.RLock()
	defer gui.spacesMutex.RUnlock()

	v, err := g.View("cmd")
	if err != nil {
		return err
	}

	msg := strings.TrimSpace(v.Buffer())
	if len(msg) != 0 {
		if msg[0] == '/' {
			if msg[1:] == "quit" {
				return gocui.ErrQuit
			}
			if strings.HasPrefix(msg[1:], "win ") {
				i, err := strconv.Atoi(msg[5:])
				if err == nil && i > 0 && i <= len(gui.spacesList) {
					gui.moveToSpace(i - 1)
				}
			}
			// Unknown command
		} else {
			gui.spacesList[gui.currentSpaceIndex].SendMessage(msg)
		}
	}

	v.Clear()
	v.SetCursor(0, 0)
	return nil
}

func (gui *GoCUI) updateSpaceList() {
	gui.Update(func(g *gocui.Gui) error {
		gui.spacesMutex.RLock()
		defer gui.spacesMutex.RUnlock()

		v, err := g.View("spaces")
		if err != nil {
			return err
		}
		v.Clear()
		for i, s := range gui.spacesList {
			color := "34"
			if i == gui.currentSpaceIndex {
				color = "37;44"
			} else if s.Highlight {
				color = "33"
			} else if s.NewMessage {
				color = "32"
			} else {
				color = "34"
			}
			fmt.Fprintf(v, "\033[32m%2d\033[0m.\033[%sm%s\033[0m\n", i+1, color, s.DisplayName())
		}

		return nil
	})
}

func (gui *GoCUI) updateMessages() {
	gui.Update(func(g *gocui.Gui) error {
		gui.spacesMutex.RLock()
		defer gui.spacesMutex.RUnlock()

		v, err := g.View("messages")
		if err != nil {
			return err
		}
		v.Clear()

		space := gui.spacesList[gui.currentSpaceIndex]
		for _, a := range space.Activities {
			if a.Verb == "post" {
				fmt.Fprintf(v, "%s %s> %s\n", a.Published.Format("15:04:05"), a.Actor.DisplayName, a.Object.DisplayName)
			}
		}

		return nil
	})

}

func (gui *GoCUI) updateSpaceStatus() {
	gui.Update(func(g *gocui.Gui) error {
		gui.spacesMutex.RLock()
		defer gui.spacesMutex.RUnlock()

		v, err := g.View("spaceStatus")
		if err != nil {
			return err
		}
		v.Clear()

		space := gui.spacesList[gui.currentSpaceIndex]

		fmt.Fprintf(v, "[%s]", space.DisplayName())
		return nil
	})
}

func (gui *GoCUI) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if _, err := g.SetView("spaces", -1, -1, 25, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
	}
	if v, err := g.SetView("messages", 25, -1, maxX, maxY-2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Autoscroll = true
		v.Frame = false
	}
	if v, err := g.SetView("spaceStatus", 25, maxY-3, maxX, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Frame = false
		v.BgColor = gocui.ColorBlue
	}
	if v, err := g.SetView("cmd", 25, maxY-2, maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Frame = false
		v.Editable = true
	}

	if _, err := g.SetCurrentView("cmd"); err != nil {
		return err
	}

	return nil
}
