from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
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


class MyButton(Button):
    def __init__(self, color=(0.5, 0.5, 0.5, 1),**kwargs):
        super().__init__(**kwargs)

        # 3 rows, 2 columns grid
        layout = GridLayout(cols=2, rows=3, size_hint=(1,1),pos=self.pos)

        self.padding_percentage = 0.02
        self.canvas.before.clear()
        self.canvas.before.clear()
        with self.canvas.before:
            self.bg_color = Color(*color)
            self.bg_rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self.update_rect_pos, pos=self.update_rect_pos)

        # Adding labels
        layout.add_widget(ColorLabel(text="TL", halign="left", valign="top", text_size = self.size))
        layout.add_widget(Label(text="TR", halign="right", valign="top", text_size = self.size))

        layout.add_widget(Label(text="CL", halign="left", valign="middle", text_size = self.size))
        layout.add_widget(ColorLabel(text="CR", halign="right", valign="middle", text_size = self.size))

        layout.add_widget(ColorLabel(text="BL", halign="left", valign="bottom", text_size = self.size))
        layout.add_widget(Label(text="BR", halign="right", valign="bottom", text_size = self.size))

        # Ensuring text alignment inside each label
        for child in layout.children:
            child.bind(size=lambda s, _: setattr(s, "text_size", s.size))

        self.add_widget(layout)
    

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

class MyApp(App):
    def build(self):
        return MyButton()

if __name__ == "__main__":
    MyApp().run()
