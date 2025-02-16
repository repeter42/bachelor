from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.graphics import Color, Rectangle

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
        # Update background size and position
        self.bg_rect.size = self.size
        self.bg_rect.pos = self.pos
        
        # Compute padding separately for width and height
        padding_x = self.width * self.padding_percentage
        padding_y = self.height * self.padding_percentage
        
        # Adjust the texture size dynamically to match the label size with padding
        self.text_size = (
            max(0, self.width - 2 * padding_x),
            max(0, self.height - 2 * padding_y)
        )

class GridButton(Button):
    def __init__(self, text, color=(0.5, 0.5, 0.5, 1), **kwargs):
        """
        :param text: tuple containing six strings to be displayed on the grid
        """
        super().__init__(**kwargs)
        self.padding_percentage = 0.02

        # Create a grid layout that fills the button
        self.layout = GridLayout(cols=2, rows=3, size_hint=(1, 1))
        # **IMPORTANT:** Add the layout to the button
        self.add_widget(self.layout)

        # Set up button background
        self.canvas.before.clear()
        with self.canvas.before:
            self.bg_color = Color(*color)
            self.bg_rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect_pos, pos=self.update_rect_pos)

        text_in = text
        # Create labels with proper alignment and binding to update text_size.
        # Top Left
        tl = Label(text=text_in[0], size_hint=(1, 1))
        # tl.halign = "left"
        # tl.valign = "top"
        tl.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        self.layout.add_widget(tl)

        # Top Right
        tr = Label(text=text_in[1], size_hint=(1, 1))
        # tr.halign = "right"
        # tr.valign = "top"
        tr.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        self.layout.add_widget(tr)

        # Center Left
        cl = Label(text=text_in[2], size_hint=(1, 1))
        # cl.halign = "left"
        # cl.valign = "middle"
        cl.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        self.layout.add_widget(cl)

        # Center Right
        cr = Label(text=text_in[3], size_hint=(1, 1))
        # cr.halign = "right"
        # cr.valign = "middle"
        cr.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        self.layout.add_widget(cr)

        # Bottom Left
        bl = Label(text=text_in[4], size_hint=(1, 1))
        # bl.halign = "left"
        # bl.valign = "bottom"
        bl.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        self.layout.add_widget(bl)

        # Bottom Right
        br = Label(text=text_in[5], size_hint=(1, 1))
        # br.halign = "right"
        # br.valign = "bottom"
        br.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        self.layout.add_widget(br)

    def update_rect_pos(self, *args):
        # Update the button's background rectangle.
        self.bg_rect.size = self.size
        self.bg_rect.pos = self.pos
        # **CRITICAL:** Update the grid layout to fill the entire button.
        self.layout.size = self.size
        self.layout.pos = self.pos


class ButtonGrid(GridLayout):
    def __init__(self, lb_detail_in,**kwargs):
        super().__init__(**kwargs)
        self.cols = 1  # Single column for labels
        self.size_hint_x = 1
        self.size_hint_y = None  # Scrollable height
        self.bind(minimum_height=self.setter('height'))  # Dynamic height
        self.row_count = 0  # Start with 0 rows
        self.buttons = []
        self.big_label = lb_detail_in

    def populate_grid(self, color):
        """
        :param color: indicates the color with which the list starts
        """
        self.clear_widgets()
        for button in reversed(self.buttons):
            if color:
                button.background_color = (0.9, 0.9, 0.9, 1)
            else:
                button.background_color = (0.8, 0.8, 0.8, 1)
            color = not color
            button.bind(on_touch_down=self.on_button_click)  # Bind touch event
            self.add_widget(button)

    def add_row(self):
        self.row_count += 1
        # text is a tuple of the 6 values displayed on the preview
        packet_info= (f"ID: {self.row_count}", "ID: \{ID\}", "ID: \{ID\}", "ID: \{ID\}", "ID: \{ID\}", "ID: \{ID\}")
        new_button = GridButton(text=packet_info, size_hint_y=None, height=60)
        self.buttons.append(new_button)  # Add new label to list
        color = False
        if self.row_count % 2 == 0:
            color = True
        self.populate_grid(color=color)  # Refresh UI with newest at the top

    def on_button_click(self, instance, touch):
        if instance.collide_point(*touch.pos):
            # Use the GridButton's method to gather all label texts
            self.big_label.text = (instance.get_combined_text() + "\n")


class EthPortTestApp(App):
    def build(self):

        ## START setting bar     --> search bar (text input), and buttons
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
        ## END setting bar

        ## START packet display --> packetlist left (label grid), packet details right (label)
        packet_display = BoxLayout(orientation="horizontal")

        ### packet details view on the right
        self.lb_detail = ColorLabel(text="", size_hint_x=1, size_hint_y=1)              # creating the label
        self.lb_detail.halign="left"
        self.lb_detail.valign="top"
        # self.lb_detail.bind(size=lambda instance, value: setattr(instance, "text_size", instance.size))
        scroll_lb_packet_detail = ScrollView(size_hint_x=0.5, size_hint_y=1)            # creating ScrollView
        scroll_lb_packet_detail.add_widget(self.lb_detail)                              # putting label in SV

        ### packet list on the left
        self.label_grid = ButtonGrid(lb_detail_in=self.lb_detail)                       # creating the label
        scroll_lb_grid_packt_list = ScrollView(size_hint_x=0.5, size_hint_y=1)          # creating ScrollView
        scroll_lb_grid_packt_list.add_widget(self.label_grid)                           # putting label in SV

        ## adding packet list and packet derails to
        packet_display.add_widget(scroll_lb_grid_packt_list)
        packet_display.add_widget(scroll_lb_packet_detail)
        ## END packet display

        # START complete layout
        layout = BoxLayout(orientation="vertical")

        layout.add_widget(top_bar)  # Top bar first
        layout.add_widget(packet_display)  # Then main content
        # END complete layout

        return layout

    def btn_add_row_click(self, instance):
        self.label_grid.add_row()  # Call method to add a row

if __name__ == "__main__":
    EthPortTestApp().run()
