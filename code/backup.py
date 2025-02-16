from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.graphics import Color, Rectangle
from kivy.metrics import dp

from backend.scan import scan_settings

class ColorLabel(Label):
    def __init__(self, color=(0.5, 0.5, 0.5, 1), **kwargs):
        super().__init__(**kwargs)
        self.padding_percentage = 0.02

        self.canvas.before.clear()
        with self.canvas.before:
            self.bg_color = Color(*color)
            self.bg_rect = Rectangle(size=self.size, pos=self.pos)

        self.bind(size=self.update_rect_pos, pos=self.update_rect_pos)

    def update_rect_pos(self, *args):
        # Update background rectangle size and position
        self.bg_rect.size = self.size
        self.bg_rect.pos = self.pos

        # Compute padding separately for width and height
        padding_x = self.width * self.padding_percentage
        padding_y = self.height * self.padding_percentage

        # Adjust text size with padding
        self.text_size = (
            max(0, self.width - 2 * padding_x),
            max(0, self.height - 2 * padding_y)
        )
        

class GridButton(Button):
    def __init__(self, text, color=(0.5, 0.5, 0.5, 1), **kwargs):
        super().__init__(**kwargs)
        self.padding_percentage = 0.02
        self.text_data = text
        self.layout = GridLayout(cols=2, rows=3, size_hint=(1, 1))
        self.add_widget(self.layout)

        self.canvas.before.clear()
        with self.canvas.before:
            self.bg_color = Color(*color)
            self.bg_rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect_pos, pos=self.update_rect_pos)

        self._populate_labels(text)

    def _populate_labels(self, text_in):
        for txt in text_in:
            lbl = Label(text=txt, size_hint=(1, 1))
            lbl.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
            self.layout.add_widget(lbl)

    def update_rect_pos(self, *args):
        self.bg_rect.size = self.size
        self.bg_rect.pos = self.pos
        self.layout.size = self.size
        self.layout.pos = self.pos

    def get_combined_text(self):
        return "\n".join(self.text_data)

    # # --- Add these methods to allow scrolling on touchscreens ---
    # def on_touch_down(self, touch):
    #     if self.collide_point(*touch.pos):
    #         # record the starting touch position
    #         self._touch_start = touch.pos
    #     return super().on_touch_down(touch)

    # def on_touch_move(self, touch):
    #     if self.collide_point(*touch.pos) and hasattr(self, "_touch_start"):
    #         # if vertical movement exceeds a small threshold, let ScrollView handle it
    #         if abs(touch.pos[1] - self._touch_start[1]) > dp(10):
    #             if touch.grab_current is self:
    #                 touch.ungrab(self)
    #             return False  # do not consume; allow parent to scroll
    #     return super().on_touch_move(touch)



class ButtonGrid(GridLayout):
    def __init__(self, lb_detail_in, **kwargs):
        super().__init__(**kwargs)
        self.cols = 1  # Single column for buttons
        self.size_hint_x = 1
        self.size_hint_y = None  # Allow dynamic height
        self.bind(minimum_height=self.setter('height'))
        self.row_count = 0
        self.buttons = []
        self.big_label = lb_detail_in

    def populate_grid(self, color):
        self.clear_widgets()
        for button in reversed(self.buttons):
            button.background_color = (0.9, 0.9, 0.9, 1) if color else (0.8, 0.8, 0.8, 1)
            color = not color
            # Bind on_release instead of on_touch_down.
            button.bind(on_release=self.on_button_click)
            self.add_widget(button)

    def add_row(self):
        self.row_count += 1
        packet_info = (
            f"ID: {self.row_count}",
            "ID: \\{ID\\}",
            "ID: \\{ID\\}",
            "ID: \\{ID\\}",
            "ID: \\{ID\\}",
            "ID: \\{ID\\}"
        )
        new_button = GridButton(text=packet_info, size_hint_y=None, height=60)
        self.buttons.append(new_button)
        color = True if self.row_count % 2 == 0 else False
        self.populate_grid(color=color)

    def on_button_click(self, instance):
        # When the button is released (i.e. a tap is complete), update the detail label.
        self.big_label.text = instance.get_combined_text() + "\n"

class EthPortTestApp(App):
    def build(self):
        # Top bar with search input and buttons.
        top_bar = BoxLayout(size_hint_y=None, height=50, spacing=5, padding=5)
        search_input = TextInput(hint_text="Search...", size_hint_x=0.4, height=50)
        btn1 = Button(text="Add Row", size_hint_x=0.15, height=50, on_press=self.btn_add_row_click)
        btn2 = Button(text="Btn 2", size_hint_x=0.15, height=50)
        btn3 = Button(text="Btn 3", size_hint_x=0.15, height=50)
        btn4 = Button(text="Btn 4", size_hint_x=0.15, height=50)
        top_bar.add_widget(search_input)
        top_bar.add_widget(btn1)
        top_bar.add_widget(btn2)
        top_bar.add_widget(btn3)
        top_bar.add_widget(btn4)

        # Packet display area: left list of packets, right details view.
        packet_display = BoxLayout(orientation="horizontal")

        # Packet details view.
        self.lb_detail = ColorLabel(text="", size_hint_x=1, size_hint_y=1)
        self.lb_detail.halign = "left"
        self.lb_detail.valign = "top"
        scroll_lb_packet_detail = ScrollView(size_hint_x=0.5, size_hint_y=1)
        scroll_lb_packet_detail.add_widget(self.lb_detail)

        # Packet list view.
        self.label_grid = ButtonGrid(lb_detail_in=self.lb_detail)
        scroll_lb_grid_packet_list = ScrollView(size_hint_x=0.5, size_hint_y=1)
        scroll_lb_grid_packet_list.add_widget(self.label_grid)

        packet_display.add_widget(scroll_lb_grid_packet_list)
        packet_display.add_widget(scroll_lb_packet_detail)

        # Complete layout.
        layout = BoxLayout(orientation="vertical")
        layout.add_widget(top_bar)
        layout.add_widget(packet_display)

        return layout

    def add_packet(self, packet):
        self.label_grid.add_row(packet)


if __name__ == "__main__":
    EthPortTestApp().run()
