import idaapi
from idaapi import GraphViewer
import idc

COVERAGE_COLOR = 0xbbffbb

class EtmCallGraphViewer(GraphViewer):
    def __init__(self, callgraph):
        GraphViewer.__init__(self, "Call graph of " + idaapi.get_root_filename())
        self.callgraph = callgraph

    def OnRefresh(self):
        self.Clear()
        id = self.AddNode(self.callgraph[0])

        for i in range(1,len(self.callgraph)):
            nxt = self.AddNode(self.callgraph[i])
            self.AddEdge(id,nxt)
            id = nxt

        self.AddEdge(id,self.AddNode("end"))

        return True

    def OnGetText(self, node_id):
        return str(self[node_id])

    def show(self):
        return self.Show()

class EtmCoverageChoose2(Choose2):
    def __init__(self, title, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(self, title, [["Function", 30], ["Instructions", 20], ["Coverage", 20]], flags = flags,
            width = width, height = height, embedded = embedded)
        self.n = 0
        self.items = []
        self.icon = 5
        self.modal = modal

    def OnClose(self):
        pass

    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show(self.modal) >= 0

    def fill(self, funcs):
        instr_sum = 0.0
        for count in funcs.values():
            instr_sum += count

        for func in funcs.items():
            self.items.append([func[0],str(func[1]),"%.02f" % (func[1] * 100 / instr_sum) + "%"])

class EtmTraceChoose2(Choose2):
    def __init__(self, title, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(self, title, [ ["pid", 10], ["Address", 20], ["Instruction", 45] ], flags = flags,
            width = width, height = height, embedded = embedded)
        self.n = 0
        self.items = []
        self.icon = 5
        self.modal = modal
        self.popup_names = ["","","","Coverage.."]
        self.coverage = {}
        self.callgraph = []
        self.is_select = False

    def OnClose(self):
        pass

    def OnSelectLine(self, n):
        self.is_select = True
        idc.Jump(int(self.items[n][1].replace("L",""),16))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnRefresh(self, n):

        if not self.is_select:
            form_title = "ETM coverage"
            form = idaapi.find_tform(form_title)

            if form != None:
                print "ETM coverage window already open. Switching to it."
                idaapi.switchto_tform(form, True)
                return n

            self.coverage_window = EtmCoverageChoose2(form_title, modal=False)
            self.coverage_window.fill(self.coverage)
            self.coverage_window.show()
            self.callgraph_window = EtmCallGraphViewer(self.callgraph)
            self.callgraph_window.show()

        self.is_select = False
        return n

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        return t

    def show(self):
        return self.Show(self.modal) >= 0

    def add_instruction(self, line):
        self.n += 1
        self.items.append(line)
        addr = int(line[1].replace("L",""),16)
        idc.SetColor(addr,idc.CIC_ITEM,COVERAGE_COLOR)
        func_name = idc.GetFunctionName(addr)
        if func_name != "":
            if func_name != self.callgraph[-1]:
                self.callgraph.append(func_name)

            if not self.coverage.get(func_name):
                self.coverage[func_name] = 1
            else:
                self.coverage[func_name] += 1

    def add_instruction_range(self, thread, addr_range):
        addr = int(addr_range[0],16)
        end_addr = int(addr_range[1],16)
        while addr <= end_addr:
            self.add_instruction([thread,hex(addr),idc.GetDisasm(addr)])
            addr += idc.ItemSize(addr)

    def add_jump_from_external(self,thread,addr,jmp_from):
        lib_name = jmp_from.split("/")[-1]
        self.n += 1
        self.items.append([thread,"0x" + addr,"from " + lib_name])
        if lib_name != self.callgraph[-1]:
            self.callgraph.append(lib_name)

    def add_jump_to_external(self,thread,addr,jmp_to):
        lib_name = jmp_to.split("/")[-1]
        self.n += 1
        self.items.append([thread,"0x" + addr,"to " + jmp_to.split("/")[-1]])
        if lib_name != self.callgraph[-1]:
            self.callgraph.append(lib_name)


class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Coresight ETM trace displayer"
    help = ""
    wanted_name = "ETM trace display"
    wanted_hotkey = "Alt-F8"

    def init(self):
        info = idaapi.get_inf_structure()

        if info.procName != "ARM" or info.filetype != idaapi.f_ELF:
            print "Support only ARM ELF"
            return idaapi.PLUGIN_SKIP

        return idaapi.PLUGIN_OK

    def run(self, arg):
        if not idaapi.autoIsOk():
            if idaapi.askyn_c(ASKBTN_CANCEL, "HIDECANCEL\n", "The autoanalysis has not finished yet.\n", "The result might be incomplete. Do you want to continue?") < ASKBTN_NO:
                return

        form_title = "ETM trace"
        form = idaapi.find_tform(form_title)

        if form != None:
            print "ETM trace window already open. Switching to it."
            idaapi.switchto_tform(form, True);
            return

        trace_file_name = idaapi.askfile_c(0, "", "Select a trace to display...");
        if len(trace_file_name) < 1:
            return

        image_name = idaapi.get_root_filename()

        f = open(trace_file_name,"r")

        #trace format: filename[0] id[1] type[2] description[3] src_addr[4] src_func_offset[5] src_image[6] =>[7] dst_addr[8] dst_func_offset[9] dst_image[10]
        start_branch = f.readline().split()

        if not start_branch:
            return

        while len(start_branch) != 11:
            start_branch = f.readline().split()
            if not start_branch:
                return

        self.c = EtmTraceChoose2(form_title, modal=False)

        self.c.callgraph.append("start")

        while True:
            next_branch = f.readline().split()
            if not next_branch:
                break

            start_branch[10] = start_branch[10].replace("(","").replace(")","")
            start_branch[6] = start_branch[6].replace("(","").replace(")","")

            if start_branch[10].split("/")[-1] != image_name and start_branch[6].split("/")[-1] != image_name:
                start_branch = next_branch
                continue

            if start_branch[10].split("/")[-1] != image_name:
                #to external lib
                self.c.add_jump_to_external(start_branch[1],start_branch[8],start_branch[10])
                start_branch = next_branch
                continue
                
            if start_branch[6].split("/")[-1] != image_name:
                #from external lib
                self.c.add_jump_from_external(start_branch[1],start_branch[4],start_branch[6])

            self.c.add_instruction_range(start_branch[1], [start_branch[8], next_branch[4]])
            start_branch = next_branch

        self.c.show()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()

