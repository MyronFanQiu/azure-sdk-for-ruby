# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # Defines values for ComputeNodeState
    #
    module ComputeNodeState
      Idle = "idle"
      Rebooting = "rebooting"
      Reimaging = "reimaging"
      Running = "running"
      Unusable = "unusable"
      Creating = "creating"
      Starting = "starting"
      WaitingForStartTask = "waitingforstarttask"
      StartTaskFailed = "starttaskfailed"
      Unknown = "unknown"
      LeavingPool = "leavingpool"
      Offline = "offline"
      Preempted = "preempted"
    end
  end
end
