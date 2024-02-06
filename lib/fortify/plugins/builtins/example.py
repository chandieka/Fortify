from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils

class ExamplePlugin(FortifyPlugin):
    _name = "example"
    _option_requirement = dict(
        option_1=dict(type=str, required=True, default="Hello World!"),
        option_2=dict(type=bool, required=False, default=False),
        option_3=dict(type=int, required=False, default=1),
        option_4=dict(type=list, required=False, default=[1, "aaa", { "1": 1}]),
        option_5=dict(type=list[str], required=False, default=["Hello", "World"]),
        option_6=dict(type=str, required=False),
        option_7=dict(type=str)
    )
    _description = "lorem ipsum"

    def action(self):
        """
        This where you put your plugin logic for doing something
        """
        super(ExamplePlugin, self).action()

        # FortifyPlguinUtils is the abstraction interface for the code
        # it help does the small stuff
        fpu = FortifyPluginUtils(
            self.options, 
            self._target_host, 
            self._result
        )

        # use the get_host_info to get the target host info
        HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info() 

        # setting plugin status
        fpu.set_success()
        fpu.set_fail()
        fpu.set_skip()

        # to add message 
        fpu.add_message("A message has appear here!!")

        # Status + message
        fpu.success_plugin("Success message!!")
        fpu.fail_plugin("Fail message!!")
        fpu.skip_plugin("Skip message!!")

        # return fpu.json_output(**self._result)
        return fpu.raw_output()
    