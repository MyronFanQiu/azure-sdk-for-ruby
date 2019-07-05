# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Resource usage statistics for a job schedule.
    #
    #
    class JobScheduleStatistics

      include MsRestAzure

      # @return [String] The URL of the statistics.
      attr_accessor :url

      # @return [DateTime] The start time of the time range covered by the
      # statistics.
      attr_accessor :start_time

      # @return [DateTime] The time at which the statistics were last updated.
      # All statistics are limited to the range between startTime and
      # lastUpdateTime.
      attr_accessor :last_update_time

      # @return [Duration] The total user mode CPU time (summed across all
      # cores and all compute nodes) consumed by all tasks in all jobs created
      # under the schedule.
      attr_accessor :user_cputime

      # @return [Duration] The total kernel mode CPU time (summed across all
      # cores and all compute nodes) consumed by all tasks in all jobs created
      # under the schedule.
      attr_accessor :kernel_cputime

      # @return [Duration] The total wall clock time of all the tasks in all
      # the jobs created under the schedule. The wall clock time is the elapsed
      # time from when the task started running on a compute node to when it
      # finished (or to the last time the statistics were updated, if the task
      # had not finished by then). If a task was retried, this includes the
      # wall clock time of all the task retries.
      attr_accessor :wall_clock_time

      # @return [Integer] The total number of disk read operations made by all
      # tasks in all jobs created under the schedule.
      attr_accessor :read_iops

      # @return [Integer] The total number of disk write operations made by all
      # tasks in all jobs created under the schedule.
      attr_accessor :write_iops

      # @return [Float] The total gibibytes read from disk by all tasks in all
      # jobs created under the schedule.
      attr_accessor :read_iogi_b

      # @return [Float] The total gibibytes written to disk by all tasks in all
      # jobs created under the schedule.
      attr_accessor :write_iogi_b

      # @return [Integer] The total number of tasks successfully completed
      # during the given time range in jobs created under the schedule. A task
      # completes successfully if it returns exit code 0.
      attr_accessor :num_succeeded_tasks

      # @return [Integer] The total number of tasks that failed during the
      # given time range in jobs created under the schedule. A task fails if it
      # exhausts its maximum retry count without returning exit code 0.
      attr_accessor :num_failed_tasks

      # @return [Integer] The total number of retries during the given time
      # range on all tasks in all jobs created under the schedule.
      attr_accessor :num_task_retries

      # @return [Duration] The total wait time of all tasks in all jobs created
      # under the schedule. The wait time for a task is defined as the elapsed
      # time between the creation of the task and the start of task execution.
      # (If the task is retried due to failures, the wait time is the time to
      # the most recent task execution.). This value is only reported in the
      # account lifetime statistics; it is not included in the job statistics.
      attr_accessor :wait_time


      #
      # Mapper for JobScheduleStatistics class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobScheduleStatistics',
          type: {
            name: 'Composite',
            class_name: 'JobScheduleStatistics',
            model_properties: {
              url: {
                client_side_validation: true,
                required: true,
                serialized_name: 'url',
                type: {
                  name: 'String'
                }
              },
              start_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'startTime',
                type: {
                  name: 'DateTime'
                }
              },
              last_update_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'lastUpdateTime',
                type: {
                  name: 'DateTime'
                }
              },
              user_cputime: {
                client_side_validation: true,
                required: true,
                serialized_name: 'userCPUTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              kernel_cputime: {
                client_side_validation: true,
                required: true,
                serialized_name: 'kernelCPUTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              wall_clock_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'wallClockTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              read_iops: {
                client_side_validation: true,
                required: true,
                serialized_name: 'readIOps',
                type: {
                  name: 'Number'
                }
              },
              write_iops: {
                client_side_validation: true,
                required: true,
                serialized_name: 'writeIOps',
                type: {
                  name: 'Number'
                }
              },
              read_iogi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'readIOGiB',
                type: {
                  name: 'Double'
                }
              },
              write_iogi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'writeIOGiB',
                type: {
                  name: 'Double'
                }
              },
              num_succeeded_tasks: {
                client_side_validation: true,
                required: true,
                serialized_name: 'numSucceededTasks',
                type: {
                  name: 'Number'
                }
              },
              num_failed_tasks: {
                client_side_validation: true,
                required: true,
                serialized_name: 'numFailedTasks',
                type: {
                  name: 'Number'
                }
              },
              num_task_retries: {
                client_side_validation: true,
                required: true,
                serialized_name: 'numTaskRetries',
                type: {
                  name: 'Number'
                }
              },
              wait_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'waitTime',
                type: {
                  name: 'TimeSpan'
                }
              }
            }
          }
        }
      end
    end
  end
end
