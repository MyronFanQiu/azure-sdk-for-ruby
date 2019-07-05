# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # A Job Schedule that allows recurring Jobs by specifying when to run Jobs
    # and a specification used to create each Job.
    #
    #
    class CloudJobSchedule

      include MsRestAzure

      # @return [String] A string that uniquely identifies the schedule within
      # the Account.
      attr_accessor :id

      # @return [String] The display name for the schedule.
      attr_accessor :display_name

      # @return [String] The URL of the Job Schedule.
      attr_accessor :url

      # @return [String] The ETag of the Job Schedule. This is an opaque
      # string. You can use it to detect whether the Job Schedule has changed
      # between requests. In particular, you can be pass the ETag with an
      # Update Job Schedule request to specify that your changes should take
      # effect only if nobody else has modified the schedule in the meantime.
      attr_accessor :e_tag

      # @return [DateTime] The last modified time of the Job Schedule. This is
      # the last time at which the schedule level data, such as the Job
      # specification or recurrence information, changed. It does not factor in
      # job-level changes such as new Jobs being created or Jobs changing
      # state.
      attr_accessor :last_modified

      # @return [DateTime] The creation time of the Job Schedule.
      attr_accessor :creation_time

      # @return [JobScheduleState] The current state of the Job Schedule.
      # Possible values include: 'active', 'completed', 'disabled',
      # 'terminating', 'deleting'
      attr_accessor :state

      # @return [DateTime] The time at which the Job Schedule entered the
      # current state.
      attr_accessor :state_transition_time

      # @return [JobScheduleState] The previous state of the Job Schedule. This
      # property is not present if the Job Schedule is in its initial active
      # state. Possible values include: 'active', 'completed', 'disabled',
      # 'terminating', 'deleting'
      attr_accessor :previous_state

      # @return [DateTime] The time at which the Job Schedule entered its
      # previous state. This property is not present if the Job Schedule is in
      # its initial active state.
      attr_accessor :previous_state_transition_time

      # @return [Schedule] The schedule according to which Jobs will be
      # created.
      attr_accessor :schedule

      # @return [JobSpecification] The details of the Jobs to be created on
      # this schedule.
      attr_accessor :job_specification

      # @return [JobScheduleExecutionInformation] Information about Jobs that
      # have been and will be run under this schedule.
      attr_accessor :execution_info

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with the schedule as metadata. The Batch service does not assign any
      # meaning to metadata; it is solely for the use of user code.
      attr_accessor :metadata

      # @return [JobScheduleStatistics] The lifetime resource usage statistics
      # for the Job Schedule. The statistics may not be immediately available.
      # The Batch service performs periodic roll-up of statistics. The typical
      # delay is about 30 minutes.
      attr_accessor :stats


      #
      # Mapper for CloudJobSchedule class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'CloudJobSchedule',
          type: {
            name: 'Composite',
            class_name: 'CloudJobSchedule',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              display_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'displayName',
                type: {
                  name: 'String'
                }
              },
              url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'url',
                type: {
                  name: 'String'
                }
              },
              e_tag: {
                client_side_validation: true,
                required: false,
                serialized_name: 'eTag',
                type: {
                  name: 'String'
                }
              },
              last_modified: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lastModified',
                type: {
                  name: 'DateTime'
                }
              },
              creation_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'creationTime',
                type: {
                  name: 'DateTime'
                }
              },
              state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'state',
                type: {
                  name: 'Enum',
                  module: 'JobScheduleState'
                }
              },
              state_transition_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'stateTransitionTime',
                type: {
                  name: 'DateTime'
                }
              },
              previous_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'previousState',
                type: {
                  name: 'Enum',
                  module: 'JobScheduleState'
                }
              },
              previous_state_transition_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'previousStateTransitionTime',
                type: {
                  name: 'DateTime'
                }
              },
              schedule: {
                client_side_validation: true,
                required: false,
                serialized_name: 'schedule',
                type: {
                  name: 'Composite',
                  class_name: 'Schedule'
                }
              },
              job_specification: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobSpecification',
                type: {
                  name: 'Composite',
                  class_name: 'JobSpecification'
                }
              },
              execution_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'executionInfo',
                type: {
                  name: 'Composite',
                  class_name: 'JobScheduleExecutionInformation'
                }
              },
              metadata: {
                client_side_validation: true,
                required: false,
                serialized_name: 'metadata',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetadataItemElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'MetadataItem'
                      }
                  }
                }
              },
              stats: {
                client_side_validation: true,
                required: false,
                serialized_name: 'stats',
                type: {
                  name: 'Composite',
                  class_name: 'JobScheduleStatistics'
                }
              }
            }
          }
        }
      end
    end
  end
end
