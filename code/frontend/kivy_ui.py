from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.graphics import Color, Rectangle
from kivy.metrics import dp

from scapy.layers.l2 import Ether
from backend.api import api_class
from multiprocessing import Process
import threading

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
        # gonna be unnecessary 
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

    # gonna be unnecessry
    def get_combined_text(self):
        return "\n".join(self.text_data)

    # --- Add these methods to allow scrolling on touchscreens ---
    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            # record the starting touch position
            self._touch_start = touch.pos
        return super().on_touch_down(touch)

    def on_touch_move(self, touch):
        if self.collide_point(*touch.pos) and hasattr(self, "_touch_start"):
            # if vertical movement exceeds a small threshold, let ScrollView handle it
            if abs(touch.pos[1] - self._touch_start[1]) > dp(10):
                if touch.grab_current is self:
                    touch.ungrab(self)
                return False  # do not consume; allow parent to scroll
        return super().on_touch_move(touch)

class ButtonGrid(GridLayout):
    def __init__(self, lb_detail_in, **kwargs):
        super().__init__(**kwargs)
        self.cols = 1  # Single column for buttons
        self.size_hint_x = 1
        self.size_hint_y = None  # Allow dynamic height
        self.bind(minimum_height=self.setter('height'))
        # self.row_count = 0
        self.buttons = []
        self.lb_detail = lb_detail_in

# needs to be recoded
# BEGIN RECODE ---------------------------------------

    def populate_grid(self, color):
        self.clear_widgets()
        for button in reversed(self.bubtn_add_row_clickttons):
            button.background_color = (0.9, 0.9, 0.9, 1) if color else (0.8, 0.8, 0.8, 1)
            color = not color
            # Bind on_release instead of on_touch_down.
            button.bind(on_release=self.on_button_click)
            self.add_widget(button)

    def add_row(self, packet):
        # self.row_count += 1
        if type(packet) != type(Ether()):
            raise TypeError


        packet_info = (
            f"ID: {packet[0]}",
            f"Proto: {packet[6]}",
            f"IP_src: {packet[4]}",
            f"IP_dst: {packet[5]}",
            f"MAC_src: {packet[1]}",
            f"MAC_dst: {packet[2]}"
        )
        new_button = GridButton(text=packet_info, size_hint_y=None, height=60)
        self.buttons.append(new_button)
        color = True if self.row_count % 2 == 0 else False
        self.populate_grid(color=color)

# END RECODE

    def on_button_click(self, instance):
        # When the button is released (i.e. a tap is complete), update the detail label.
        self.lb_detail.text = instance.get_combined_text() + "\n"

class EthPortTestApp(App):
    def build(self):

        self.api = api_class()

        # Top bar buttons.
        top_bar = BoxLayout(size_hint_y=None, height=50, spacing=5, padding=5)
        btn_start_listen = Button(text="start listen", size_hint_x=0.15, height=50, on_press=self.btn_start_listening_click)
        btn_stop_listen = Button(text="stop listen", size_hint_x=0.15, height=50, on_press=self.btn_stop_listening_click)
        btn_clear_packets = Button(text="clear packets", size_hint_x=0.15, height=50, on_press=self.btn_clear_packets_click)
        btn_test_network = Button(text="test network", size_hint_x=0.15, height=50, on_press=self.btn_test_network_click)
        self.writing_pcap_ui = True
        btn_save_to_pcap = Button(text="writing pcap: yes", size_hint_x=0.15, height=50, on_press=self.btn_save_to_pcap_click)
        btn_swich_view = Button(text="switch view", size_hint_x=0.15, height=50, on_press=self.btn_switch_view_click)
        top_bar.add_widget(btn_start_listen)
        top_bar.add_widget(btn_stop_listen)
        top_bar.add_widget(btn_clear_packets)
        top_bar.add_widget(btn_test_network)
        top_bar.add_widget(btn_save_to_pcap)
        top_bar.add_widget(btn_swich_view)

        # Packet display area: left list of packets, right details view
        packet_display = BoxLayout(orientation="horizontal")

        # Packet details view
        self.lb_detail = ColorLabel(text="", size_hint_x=1, size_hint_y=1)
        self.lb_detail.halign = "left"
        self.lb_detail.valign = "top"
        scroll_lb_packet_detail = ScrollView(size_hint_x=0.5, size_hint_y=1)
        scroll_lb_packet_detail.add_widget(self.lb_detail)

        # Packet list view
        self.label_grid = ButtonGrid(lb_detail_in=self.lb_detail)
        scroll_lb_grid_packet_list = ScrollView(size_hint_x=0.5, size_hint_y=1)
        scroll_lb_grid_packet_list.add_widget(self.label_grid)

        packet_display.add_widget(scroll_lb_grid_packet_list)
        packet_display.add_widget(scroll_lb_packet_detail)
        
        # FloatLayout to manage overlay
        self.main_view = FloatLayout()

        # Add packet_display as the base layer
        self.main_view.add_widget(packet_display)

        # Network Overlay view (Initially hidden)
        self.lb_network_view = ColorLabel(
            text="NETWORK STATUS",
            color=(0.6, 0.6, 0.6, 1),
            size_hint=(1, 1),  # Adjust size as needed
            # pos_hint={"center_x": 0.5, "center_y": 0.5},
            pos_hint={"x": 0, "y": 0},
            opacity=0,  # Initially hidden
            disabled=True
        )
        self.lb_network_view.halign = "left"
        self.lb_network_view.valign = "top"
        scroll_lb_network_view = ScrollView()
        scroll_lb_network_view.add_widget(self.lb_network_view)
        self.main_view.add_widget(scroll_lb_network_view)

        # Complete layout.
        layout = BoxLayout(orientation="vertical")
        layout.add_widget(top_bar)
        layout.add_widget(self.main_view)

        return layout

    def add_packet(self, packet):
        self.label_grid.add_row(packet)

    def btn_start_listening_click(self, instance):
        #self.sniffing_process = Process(target=api.start_sniffing)
        self.sniffing_process = Process(target=self.api.start_sniffing)
        self.sniffing_process.start()

    def btn_stop_listening_click(self, instance):
        # api.stop_sniffing()
        self.api.stop_sniffing()
    
    def btn_clear_packets_click(self, instance):
        # api.clear_packets()
        self.api.clear_packets()

    def btn_test_network_click(self, instance):
        # connectivity_info = api.test_network()
        connectivity_info = self.api.test_network()
        # dhcp_info = api.get_dhcp_info()
        dhcp_info = self.api.get_dhcp_info()
        net_print = "NETWORK STATUS\n\nCONNECTIVITY" + connectivity_info + "\n\n" + dhcp_info
        # print(connectivity_info)
        # print(dhcp_info)
        self.lb_network_view.text = net_print 
    
    def btn_save_to_pcap_click(self, instance):
        self.writing_pcap_ui = not self.writing_pcap_ui
        if self.writing_pcap_ui:
            instance.text = "writing pcap: yes"
            # api.set_write_to_pcap(True)
            self.api.set_write_to_pcap(True)
        else:
            instance.text = "writing pcap: no"
            # api.set_write_to_pcap(False)
            self.api.set_write_to_pcap(False)

    def btn_switch_view_click(self, instance):
        # Toggle visibility of the overlay
        if self.lb_network_view.opacity == 0:
            self.lb_network_view.opacity = 1
            self.lb_network_view.disabled = False
        else:
            self.lb_network_view.opacity = 0
            self.lb_network_view.disabled = True


my_eth_tester = EthPortTestApp()
if __name__ == "__main__":
    my_eth_tester.run()
