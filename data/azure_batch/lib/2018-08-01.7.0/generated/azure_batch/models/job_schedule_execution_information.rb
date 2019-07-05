# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # Contains information about jobs that have been and will be run under a
    # job schedule.
    #
    #
    class JobScheduleExecutionInformation

      include MsRestAzure

      # @return [DateTime] The next time at which a job will be created under
      # this schedule. This property is meaningful only if the schedule is in
      # the active state when the time comes around. For example, if the
      # schedule is disabled, no job will be created at nextRunTime unless the
      # job is enabled before then.
      attr_accessor :next_run_time

      # @return [RecentJob] Information about the most recent job under the job
      # schedule. This property is present only if the at least one job has run
      # under the schedule.
      attr_accessor :recent_job

      # @return [DateTime] The time at which the schedule ended. This property
      # is set only if the job schedule is in the completed state.
      attr_accessor :end_time


      #
      # Mapper for JobScheduleExecutionInformation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobScheduleExecutionInformation',
          type: {
            name: 'Composite',
            class_name: 'JobScheduleExecutionInformation',
            model_properties: {
              next_run_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nextRunTime',
                type: {
                  name: 'DateTime'
                }
              },
              recent_job: {
                client_side_validation: true,
                required: false,
                serialized_name: 'recentJob',
                type: {
                  name: 'Composite',
                  class_name: 'RecentJob'
                }
              },
              end_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'endTime',
                type: {
                  name: 'DateTime'
                }
              }
            }
          }
        }
      end
    end
  end
end
